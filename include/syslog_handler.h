#ifndef WS_SYSLOG_HANDLER_H
#define WS_SYSLOG_HANDLER_H

/* RFC 5424 syslog wrapper */

void ws_syslog_open(const char *ident, int facility);
void ws_syslog_close(void);
void ws_syslog_msg(int priority, const char *fmt, ...);

/* Priority levels (matching syslog.h) */
#define WS_LOG_ERR    3
#define WS_LOG_WARN   4
#define WS_LOG_INFO   6
#define WS_LOG_DEBUG  7

#endif /* WS_SYSLOG_HANDLER_H */
