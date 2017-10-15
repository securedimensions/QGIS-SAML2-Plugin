#include "qgsauthsaml2method.h"
#include "qgsauthsaml2edit.h"
#include "qgsnetworkaccessmanager.h"
#include "qgsauthmanager.h"
#include "qgslogger.h"
#include "qgsmessagelog.h"

#include <QDomDocument>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QBuffer>
#include <QNetworkCookie>
#include <QDomNamedNodeMap>

static const QString AUTH_METHOD_KEY = "SAML2";
static const QString AUTH_METHOD_DESCRIPTION = "SAML2 authentication";

QMap<QString, QgsAuthMethodConfig> QgsAuthSAML2Method::mAuthConfigCache = QMap<QString, QgsAuthMethodConfig>();

namespace
{
  QDomNode namedItemNS(const QDomNodeList &nodes, const char *nsURI, const char *localName)
  {
    QDomNode n;
    int ix, count = nodes.count();
    for (ix=0; ix < count; ix++)
    {
      n = nodes.at(ix);
      //QgsDebugMsg(QString("element name: %1 nsURI: %2").arg(n.localName(),n.namespaceURI()));		
      if ((n.localName() == localName) && (n.namespaceURI() == nsURI))
        return n;
    }
    return QDomNode();
  }

  QString getECPEndpoint(const QString& url)
  {
    QString ecp/*="https://idp.tb13.secure-dimensions.de/idp/profile/SAML2/SOAP/ECP"*/;
    const QString BINDINGURI="urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
    const QString TAGNAME="SingleSignOnService";
    QEventLoop networkLoop;
    QNetworkReply* idpReply = QgsNetworkAccessManager::instance()->get( QNetworkRequest( url ) );
    QObject::connect( idpReply, SIGNAL( finished() ), &networkLoop, SLOT( quit() ) );
    networkLoop.exec();
    QDomDocument idpMetadata;
    QByteArray response;
    if ( idpReply->error() == QNetworkReply::NoError )
    {
      response = idpReply->readAll();
      if ( response.isEmpty() )
      {
        QString errorMsg = QStringLiteral( "Update request FAILED: empty metadata response from IdP: %1" ).arg( idpReply->errorString() );
        QgsMessageLog::logMessage( errorMsg, AUTH_METHOD_KEY, QgsMessageLog::CRITICAL );
        return false;
      }
    }
    else
    {
      QString errorMsg = QStringLiteral( "Update request FAILED: metadata request to IdP failed: %1" ).arg( idpReply->errorString() );
      QgsMessageLog::logMessage( errorMsg, AUTH_METHOD_KEY, QgsMessageLog::CRITICAL );
      return false;
    }
    
    idpMetadata.setContent( response, true );
    QDomNodeList ssoNodes = idpMetadata.elementsByTagName( TAGNAME );
    for( int i = 0; i < ssoNodes.count(); ++i )
    {
      QDomNamedNodeMap attrs= ssoNodes.at(i).attributes();
      if ( attrs.contains( "Binding" ) )
      {
        if( attrs.namedItem( "Binding" ).nodeValue() == BINDINGURI )
        {
          ecp = attrs.namedItem( "Location" ).nodeValue();
          break;
        }
      }
    }
    return ecp;
  }

}


QgsAuthSAML2Method::QgsAuthSAML2Method()
  : QgsAuthMethod()
{
  setVersion( 1 );
  setExpansions( QgsAuthMethod::NetworkRequest | QgsAuthMethod::NetworkReply );
  setDataProviders( QStringList()
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

  QString errorMsg;
  QEventLoop networkLoop;
  QByteArray spECPResponse;
  QByteArray idpECPResponse;
  QgsNetworkAccessManager* nam = QgsNetworkAccessManager::instance();
  QList<QNetworkCookie> cookies;

  QgsAuthMethodConfig mconfig = getMethodConfig( authcfg );
  if ( !mconfig.isValid() )
  {
    errorMsg = QStringLiteral( "Update request config FAILED for authcfg: %1: config invalid" ).arg( authcfg );
    QgsMessageLog::logMessage( errorMsg, AUTH_METHOD_KEY, QgsMessageLog::CRITICAL );
    return false;
  }

  request.setAttribute( QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::PreferNetwork );
  request.setAttribute( QNetworkRequest::CacheSaveControlAttribute, true );

  //  the ECP URI
  const char *nsECPURI = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";

  // signal to the SP that we understand SAML2 ECP
  request.setRawHeader("PAOS", "ver=\"urn:liberty:paos:2003-08\";\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"");
  request.setRawHeader("Accept", "text/xml; application/vnd.paos+xml");

  /* Wait until reply is finished */
  /* this now contains the ecp response from the SP and not the capabilities*/
  QNetworkReply* mSPReply = nam->get( request );
  connect( mSPReply, SIGNAL( finished() ), &networkLoop, SLOT( quit() ) );
  networkLoop.exec();
  
  if ( mSPReply->error() == QNetworkReply::NoError )
  {
    spECPResponse = mSPReply->readAll();

    if ( spECPResponse.isEmpty() )
    {
      QString errorMsg = QStringLiteral( "Update request FAILED: empty ECP response from SP: %1" ).arg( mSPReply->errorString() );
      QgsMessageLog::logMessage( errorMsg, AUTH_METHOD_KEY, QgsMessageLog::CRITICAL );
      return false;
    }
  }
  else
  {
    QString errorMsg = QStringLiteral( "Update request FAILED: ECP Response from SP failed: %1" ).arg( mSPReply->errorString() );
    QgsMessageLog::logMessage( errorMsg, AUTH_METHOD_KEY, QgsMessageLog::CRITICAL );
    return false;
  }

  QgsDebugMsg( QString( "ECP Response from SP: %1" ).arg( spECPResponse.data() ) );


  // check if the response contains the PAOS response from the SP
  if (spECPResponse.indexOf(nsECPURI) != -1)
  {
    QDomDocument docFromSP, docFromIdP;
    QString acsURL,rsValue;
    QString errorMsg;
    int errorLine, errorColumn;
    if ( docFromSP.setContent( spECPResponse, true, &errorMsg, &errorLine, &errorColumn ) ) 
    {
      QDomNode headerNode = namedItemNS(docFromSP.documentElement().childNodes(), "http://schemas.xmlsoap.org/soap/envelope/", "Header");
      QDomNode bodyNode = namedItemNS(docFromSP.documentElement().childNodes(), "http://schemas.xmlsoap.org/soap/envelope/", "Body");
      QDomNode relayState = namedItemNS(headerNode.childNodes(), nsECPURI, "RelayState");
      rsValue = relayState.toElement().text();
      QgsDebugMsg( QString( "RelayState: %1" ).arg( rsValue) );

      QDomNode authnRequest = namedItemNS(bodyNode.childNodes(), "urn:oasis:names:tc:SAML:2.0:protocol", "AuthnRequest");
      acsURL = authnRequest.toElement().attribute("AssertionConsumerServiceURL");
      QgsDebugMsg( QString( "acsURL: %1" ).arg( acsURL) );

      QDomNode paosRequest = namedItemNS(headerNode.childNodes(), "urn:liberty:paos:2003-08", "Request");
      QDomNode ecpRequest = namedItemNS(headerNode.childNodes(), nsECPURI,"Request");

    }
    else
    {
      errorMsg = QStringLiteral( "Update request config FAILED for authcfg: %1: could not create DOM from ECP response from SP" ).arg( authcfg );
      QgsMessageLog::logMessage( errorMsg, AUTH_METHOD_KEY, QgsMessageLog::CRITICAL );
      return false;
    }
    // modify the RAW data to preserve the Digital Signature
    // we CANNOT do this via DOM processing...
    QByteArray dataToIdP = spECPResponse;
    int ix1 = dataToIdP.indexOf("Header>") + 7;
    int ix2 = dataToIdP.indexOf("Header>", ix1) + 7;
    dataToIdP.remove(ix1, ix2-ix1);
    dataToIdP.insert(ix1-1,'/');

    QNetworkRequest requestToIdP( QUrl( getECPEndpoint( mconfig.config( "providerurl" ) ) ) );
    // in case the user has saved username/password in the configuration, it must
    // be applied to the IdP not the SP
    QString username = mconfig.config( "username" );
    QString password = mconfig.config( "password" );

    if ( !username.isEmpty() )
    {
      requestToIdP.setRawHeader( "Authorization", "Basic " + QString( "%1:%2" ).arg( username, password ).toAscii().toBase64() );
    }

    requestToIdP.setAttribute( QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::PreferNetwork );
    requestToIdP.setAttribute( QNetworkRequest::CacheSaveControlAttribute, false );

    // signal SAML2 ECP to the IdP
    requestToIdP.setHeader(QNetworkRequest::ContentTypeHeader, "text/xml");
    // relay the modified ECP message to IdP
    QgsDebugMsg( QString( "ECP message to IdP: %1" ).arg( QString(dataToIdP)) );
    /* Wait until reply is finished */    
    QNetworkReply* mIdPReply = nam->post( requestToIdP , dataToIdP);
    connect( mIdPReply, SIGNAL( finished() ), &networkLoop, SLOT( quit() ) );
    networkLoop.exec();
    // we have a response from the IdP
    if ( mIdPReply->error() == QNetworkReply::NoError )
    {
      idpECPResponse = mIdPReply->readAll();

      if ( idpECPResponse.isEmpty() )
      {
        QString errorMsg = QStringLiteral( "Update request FAILED: empty ECP response from IdP: %1" ).arg( mIdPReply->errorString() );
        QgsMessageLog::logMessage( errorMsg, AUTH_METHOD_KEY, QgsMessageLog::CRITICAL );
        return false;
      }
    }
    else
    {
      QString errorMsg = QStringLiteral( "Update request FAILED: ECP Response from IdP failed: %1" ).arg( mIdPReply->errorString() );
      QgsMessageLog::logMessage( errorMsg, AUTH_METHOD_KEY, QgsMessageLog::CRITICAL );
      return false;
    }

    QgsDebugMsg( QString( "ECP Response from IdP: %1" ).arg( idpECPResponse.constData() ) );
    if ( docFromIdP.setContent( idpECPResponse, true, &errorMsg, &errorLine, &errorColumn ) ) 
    {
      QDomNode headerNode = namedItemNS(docFromIdP.documentElement().childNodes(), "http://schemas.xmlsoap.org/soap/envelope/", "Header");
      QString relayState = QString ("<ecp:RelayState xmlns:ecp=\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\" " + headerNode.prefix() + ":actor=\"http://schemas.xmlsoap.org/soap/actor/next\" " + headerNode.prefix() + ":mustUnderstand=\"1\">" + rsValue + "</ecp:RelayState>");
      idpECPResponse.replace(QString("<%1:Header>").arg(headerNode.prefix()).toAscii().data(),QString("<%1:Header>%2").arg(headerNode.prefix(),relayState).toAscii().data());
    }
    else
    {
      errorMsg = QStringLiteral( "Update request config FAILED for authcfg: %1: could not create DOM from ECP response from SP" ).arg( authcfg );
      QgsMessageLog::logMessage( errorMsg, AUTH_METHOD_KEY, QgsMessageLog::CRITICAL );
      return false;
    }

    QgsDebugMsg( QString( "ECP message to SP: %1" ).arg( QString(idpECPResponse) ) );

    // send modified IdP response to the SP - this contains the captured RelayState
    QNetworkRequest requestToSP ( acsURL);
    requestToSP.setAttribute( QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::PreferNetwork );
    requestToSP.setAttribute( QNetworkRequest::CacheSaveControlAttribute, false );

    QgsDebugMsg( QString( "requesting capabilities via ECP with URL: %1" ).arg( acsURL ) );
    requestToSP.setHeader(QNetworkRequest::ContentTypeHeader, "text/xml; application/vnd.paos+xml");

    /* Send request for cookies */  
    QNetworkReply* capabilitiesReply = nam->post( requestToSP, idpECPResponse );
    connect( capabilitiesReply, SIGNAL( finished() ), &networkLoop, SLOT( quit() ) );
    networkLoop.exec();
    QVariant cookieData;
    if ( capabilitiesReply->error() == QNetworkReply::NoError )
    {
      cookieData = capabilitiesReply->header( QNetworkRequest::SetCookieHeader );
      if ( !cookieData.isValid() )
      {
        QString errorMsg = QStringLiteral( "Update request FAILED: no cookies from SP: %1" ).arg( capabilitiesReply->errorString() );
        QgsMessageLog::logMessage( errorMsg, AUTH_METHOD_KEY, QgsMessageLog::CRITICAL );
        return false;
      }
      return true;
    }
    else
    {
      QString errorMsg = QStringLiteral( "Update request FAILED: ECP Response from SP failed: %1" ).arg( capabilitiesReply->errorString() );
      QgsMessageLog::logMessage( errorMsg, AUTH_METHOD_KEY, QgsMessageLog::CRITICAL );
      return false;
    }
  }
  return true;
}

bool QgsAuthSAML2Method::updateDataSourceUriItems( QStringList &connectionItems, const QString &authcfg,
  const QString &dataprovider )
{
  Q_UNUSED( dataprovider )
  Q_UNUSED( connectionItems )
  Q_UNUSED( authcfg )
  return true;
}

bool QgsAuthSAML2Method::updateNetworkReply( QNetworkReply *reply, const QString &authcfg, const QString &dataprovider )
{
  Q_UNUSED( dataprovider )
  Q_UNUSED( reply )
  Q_UNUSED( authcfg )
  return true;
}

void QgsAuthSAML2Method::updateMethodConfig( QgsAuthMethodConfig &mconfig )
{
  if ( mconfig.hasConfig( "oldconfigstyle" ) )
  {
    QgsDebugMsg( "Updating old style auth method config" );

    QStringList conflist = mconfig.config( "oldconfigstyle" ).split( "|||" );
    mconfig.setConfig( "username", conflist.at( 1 ) );
    mconfig.setConfig( "password", conflist.at( 2 ) );
    mconfig.setConfig( "federationurl", conflist.at( 3 ) );
    mconfig.setConfig( "providerurl", conflist.at( 4 ) );
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

//////////////////////////////////////////////
// Plugin externals
//////////////////////////////////////////////

/**
* Required class factory to return a pointer to a newly created object
*/
QGISEXTERN QgsAuthSAML2Method *classFactory()
{
  return new QgsAuthSAML2Method();
}

/** Required key function (used to map the plugin to a data store type)
*/
QGISEXTERN QString authMethodKey()
{
  return AUTH_METHOD_KEY;
}

/**
* Required description function
*/
QGISEXTERN QString description()
{
  return AUTH_METHOD_DESCRIPTION;
}

/**
* Required isAuthMethod function. Used to determine if this shared library
* is an authentication method plugin
*/
QGISEXTERN bool isAuthMethod()
{
  return true;
}

/**
* Optional class factory to return a pointer to a newly created edit widget
*/
QGISEXTERN QgsAuthSAML2Edit *editWidget( QWidget *parent )
{
  return new QgsAuthSAML2Edit( parent );
}

/**
* Required cleanup function
*/
QGISEXTERN void cleanupAuthMethod() // pass QgsAuthMethod *method, then delete method  ?
{
}