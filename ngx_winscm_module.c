/*
 * Copyright 2022, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <windows.h>

static volatile wchar_t *wname_global = NULL;

static size_t widen(ngx_conf_t *cf, const char *src, size_t src_len, wchar_t *dest, size_t dest_buf_len) {
    int chars_copied = MultiByteToWideChar(CP_UTF8, 0, src, (int)src_len + 1, dest, (int)dest_buf_len);
    if (0 == chars_copied) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
            "'MultiByteToWideChar' error, input: [%s], code: [%d]", src, GetLastError());
    }
    return (size_t)chars_copied - 1;
}

static int is_utility_run(ngx_conf_t *cf) {
    wchar_t *wcline = GetCommandLineW();
    wchar_t prev = L'\0';
    for (size_t i = 0;; i++) {
        wchar_t cur = wcline[i];
        if (L'\0' == cur) {
            break;
        }
        if (L'-' == prev && (L't' == cur || L'T' == cur || L's' == cur)) {
            return 1;
        }
        prev = cur;
    }
    return 0;
}

static DWORD set_service_status(SERVICE_STATUS_HANDLE ha, DWORD status) {
    SERVICE_STATUS st = {
        .dwServiceType = SERVICE_WIN32_OWN_PROCESS,
        .dwCurrentState = status,
        .dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        .dwWin32ExitCode = NO_ERROR,
        .dwServiceSpecificExitCode = 0,
        .dwCheckPoint = SERVICE_RUNNING == status || SERVICE_STOPPED == status ? 0 : 1,
        .dwWaitHint = 0};
    return SetServiceStatus(ha, &st);
}

DWORD service_control_handler(DWORD step, DWORD _1, LPVOID _2, LPVOID ha_ptr) {
    SERVICE_STATUS_HANDLE ha = *((SERVICE_STATUS_HANDLE *)ha_ptr);
    if (SERVICE_CONTROL_STOP == step || SERVICE_CONTROL_SHUTDOWN == step)
    {
        DWORD success = set_service_status(ha, SERVICE_STOP_PENDING);
        if (success > 0)
        {
            set_service_status(ha, SERVICE_STOPPED);
        }
    }
    return NO_ERROR;
}

void service_main(DWORD _, LPWSTR *args) {
    // The first parameter contains the number of arguments being passed to the service in the second parameter.
    // There will always be at least one argument. The second parameter is a pointer to an array of string pointers.
    // The first item in the array is always the service name.
    LPWSTR name = *args;
    // this pointer is leaked only once on startup
    SERVICE_STATUS_HANDLE *ha_ptr = (SERVICE_STATUS_HANDLE *)malloc(sizeof(SERVICE_STATUS_HANDLE *));
    *ha_ptr = NULL;

    // register the handler function for the service
    SERVICE_STATUS_HANDLE ha = RegisterServiceCtrlHandlerExW(name, service_control_handler, (LPVOID)ha_ptr);
    if (NULL == ha) {
        // note: it may be better to report it somehow
        return;
    }
    *ha_ptr = ha;
    DWORD pending_success = set_service_status(ha, SERVICE_START_PENDING);
    if (pending_success > 0) {
        set_service_status(ha, SERVICE_RUNNING);
    }
}

void start_dispatcher(wchar_t *wname) {
    SERVICE_TABLE_ENTRYW st[] = {
        {wname, service_main},
        {NULL, NULL}
    };

    // Connects the main thread of a service process to the service control
    // manager, which causes the thread to be the service control dispatcher
    // thread for the calling process. This call returns when the service has
    // stopped. The process should simply terminate when the call returns.
    DWORD success = StartServiceCtrlDispatcherW(st);
    if (0 != success) {
        //Sleep(3000);
        char buf[1<<7];
        memset(buf, '\0', 1<<7);
        sprintf(buf, "taskkill /f /t /pid %d", GetCurrentProcessId());
        system(buf);
    }
    // TODO: log
}

DWORD WINAPI worker_fun(LPVOID _) {
    start_dispatcher(wname_global);
    return 0;
}

static char *winscm_config(ngx_conf_t *cf, ngx_command_t *cmd, void *_) {
    if (is_utility_run(cf)) {
        return NGX_CONF_OK;
    }
    ngx_str_t *elts = cf->args->elts;
    ngx_str_t *name = &elts[1];
    if (NULL == name->data || 0 == name->len) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "Invalid empty 'winscm' config value");
        return NGX_CONF_ERROR;
    }
    if (name->len > 1 << 7) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "'winscm' config value is too long,"
                " max lenght: [%d], actual length: [%d]", 1 << 7, name->len);
        return NGX_CONF_ERROR;
    }
    wchar_t wname[1 << 8];
    memset(wname, '\0', sizeof(wchar_t) * (1 << 8));
    size_t wlen = widen(cf, (const char *)name->data, name->len, wname, 1 << 8);
    if (0 == wlen) {
        return NGX_CONF_ERROR;
    }

    SECURITY_ATTRIBUTES mutext_attrs = {
        .nLength = sizeof(SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = NULL,
        .bInheritHandle = FALSE
    };
    HANDLE mutex = CreateMutexW(&mutext_attrs, TRUE, wname);
    if (NULL == mutex) {
        return NGX_CONF_ERROR;
    }
    if (ERROR_ALREADY_EXISTS == GetLastError()) {
        CloseHandle(mutex);
        return NGX_CONF_OK;
    }

    wname_global = (wchar_t*) malloc(sizeof(wchar_t) * (wlen + 1));
    if (NULL == wname_global) {
        return NGX_CONF_ERROR;
    }
    memcpy(wname_global, wname, sizeof(wchar_t) * (wlen + 1));

    HANDLE th = CreateThread( 
        NULL,
        0,
        worker_fun,
        NULL,
        0,
        NULL);
    if (NULL == th) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "winscm, thread error: [%d]", GetLastError());
        return NGX_CONF_ERROR;
    }


    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "winscm, wlen: [%d]", wlen);

    return NGX_CONF_OK;
}

static ngx_command_t conf_desc[] = {
    {ngx_string("winscm"),
     NGX_MAIN_CONF | NGX_CONF_TAKE1,
     winscm_config,
     0,
     0,
     NULL},
    ngx_null_command /* command termination */
};

static ngx_core_module_t module_ctx = {
    ngx_string("winscm"),
    NULL,
    NULL
};

ngx_module_t ngx_winscm_module = {
    NGX_MODULE_V1,
    &module_ctx,     /* module context */
    conf_desc,       /* module directives */
    NGX_CORE_MODULE, /* module type */
    NULL,            /* init master */
    NULL,            /* init module */
    NULL,            /* init process */
    NULL,            /* init thread */
    NULL,            /* exit thread */
    NULL,            /* exit process */
    NULL,            /* exit master */
    NGX_MODULE_V1_PADDING
};
