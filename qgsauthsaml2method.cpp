#include "qgsauthsaml2method.h"
#include "qgsauthsaml2edit.h"

#include "qgsauthmanager.h"
#include "qgslogger.h"

static const QString AUTH_METHOD_KEY = "SAML2";
static const QString AUTH_METHOD_DESCRIPTION = "SAML2 authentication";

QMap<QString, QgsAuthMethodConfig> QgsAuthSAML2Method::mAuthConfigCache = QMap<QString, QgsAuthMethodConfig>();


QgsAuthSAML2Method::QgsAuthSAML2Method()
    : QgsAuthMethod()
{
    setVersion( 2 );
    setExpansions( QgsAuthMethod::NetworkRequest | QgsAuthMethod::DataSourceURI );
    setDataProviders( QStringList()
                      << "postgres"
                      << "db2"
                      << "ows"
                      << "wfs"  // convert to lowercase
                      << "wcs"
                      << "wms" );
}

QgsAuthSAML2Method::~QgsAuthSAML2Method()
{
}

QString QgsAuthSAML2Method::key() const
{
    return AUTH_METHOD_KEY;
}

QString QgsAuthSAML2Method::description() const
{
    return AUTH_METHOD_DESCRIPTION;
}

QString QgsAuthSAML2Method::displayDescription() const
{
    return tr( "SAML2 authentication" );
}

bool QgsAuthSAML2Method::updateNetworkRequest( QNetworkRequest &request, const QString &authcfg,
                                               const QString &dataprovider )
{
    Q_UNUSED( dataprovider )

    QgsAuthMethodConfig mconfig = getMethodConfig( authcfg );
    if ( !mconfig.isValid() )
    {
        QgsDebugMsg( QString( "Update request config FAILED for authcfg: %1: config invalid" ).arg( authcfg ) );
        return false;
    }

    QString username = mconfig.config( "username" );
    QString password = mconfig.config( "password" );

    if ( !username.isEmpty() )
    {
        request.setRawHeader( "Authorization", "SAML2 " + QString( "%1:%2" ).arg( username, password ).toAscii().toBase64() );
    }
    return true;
}

bool QgsAuthSAML2Method::updateDataSourceUriItems( QStringList &connectionItems, const QString &authcfg,
                                                   const QString &dataprovider )
{
    Q_UNUSED( dataprovider )
    QgsAuthMethodConfig mconfig = getMethodConfig( authcfg );
    if ( !mconfig.isValid() )
    {
        QgsDebugMsg( QString( "Update URI items FAILED for authcfg: %1: basic config invalid" ).arg( authcfg ) );
        return false;
    }

    QString username = mconfig.config( "username" );
    QString password = mconfig.config( "password" );

    if ( username.isEmpty() )
    {
        QgsDebugMsg( QString( "Update URI items FAILED for authcfg: %1: username empty" ).arg( authcfg ) );
        return false;
    }

    QString userparam = "user='" + escapeUserPass( username ) + '\'';
    int userindx = connectionItems.indexOf( QRegExp( "^user='.*" ) );
    if ( userindx != -1 )
    {
        connectionItems.replace( userindx, userparam );
    }
    else
    {
        connectionItems.append( userparam );
    }

    QString passparam = "password='" + escapeUserPass( password ) + '\'';
    int passindx = connectionItems.indexOf( QRegExp( "^password='.*" ) );
    if ( passindx != -1 )
    {
        connectionItems.replace( passindx, passparam );
    }
    else
    {
        connectionItems.append( passparam );
    }

    return true;
}

void QgsAuthSAML2Method::updateMethodConfig( QgsAuthMethodConfig &mconfig )
{
    if ( mconfig.hasConfig( "oldconfigstyle" ) )
    {
        QgsDebugMsg( "Updating old style auth method config" );

        QStringList conflist = mconfig.config( "oldconfigstyle" ).split( "|||" );
        mconfig.setConfig( "realm", conflist.at( 0 ) );
        mconfig.setConfig( "username", conflist.at( 1 ) );
        mconfig.setConfig( "password", conflist.at( 2 ) );
        mconfig.removeConfig( "oldconfigstyle" );
    }

    // TODO: add updates as method version() increases due to config storage changes
}

void QgsAuthSAML2Method::clearCachedConfig( const QString &authcfg )
{
    removeMethodConfig( authcfg );
}

QgsAuthMethodConfig QgsAuthSAML2Method::getMethodConfig( const QString &authcfg, bool fullconfig )
{
    QgsAuthMethodConfig mconfig;

    // check if it is cached
    if ( mAuthConfigCache.contains( authcfg ) )
    {
        mconfig = mAuthConfigCache.value( authcfg );
        QgsDebugMsg( QString( "Retrieved config for authcfg: %1" ).arg( authcfg ) );
        return mconfig;
    }

    // else build basic bundle
    if ( !QgsAuthManager::instance()->loadAuthenticationConfig( authcfg, mconfig, fullconfig ) )
    {
        QgsDebugMsg( QString( "Retrieve config FAILED for authcfg: %1" ).arg( authcfg ) );
        return QgsAuthMethodConfig();
    }

    // cache bundle
    putMethodConfig( authcfg, mconfig );

    return mconfig;
}

void QgsAuthSAML2Method::putMethodConfig( const QString &authcfg, const QgsAuthMethodConfig& mconfig )
{
    QgsDebugMsg( QString( "Putting basic config for authcfg: %1" ).arg( authcfg ) );
    mAuthConfigCache.insert( authcfg, mconfig );
}

void QgsAuthSAML2Method::removeMethodConfig( const QString &authcfg )
{
    if ( mAuthConfigCache.contains( authcfg ) )
    {
        mAuthConfigCache.remove( authcfg );
        QgsDebugMsg( QString( "Removed basic config for authcfg: %1" ).arg( authcfg ) );
    }
}
