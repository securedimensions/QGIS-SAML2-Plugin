#ifndef QGSAUTHSAMLMETHOD_GLOBAL_H
#define QGSAUTHSAMLMETHOD_GLOBAL_H

#include <QtCore/qglobal.h>

#if defined(QGSAUTHSAMLMETHOD_LIBRARY)
#  define QGSAUTHSAMLMETHODSHARED_EXPORT Q_DECL_EXPORT
#else
#  define QGSAUTHSAMLMETHODSHARED_EXPORT Q_DECL_IMPORT
#endif

#endif // QGSAUTHSAMLMETHOD_GLOBAL_H
