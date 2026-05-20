#ifndef log_h
#define log_h

#define LOGI(...)
#define LOGD(...)
#define LOGE(...)
#define LOGV(...)

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#endif
