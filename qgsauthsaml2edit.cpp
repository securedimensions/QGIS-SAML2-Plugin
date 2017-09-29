#include "qgsauthsaml2edit.h"
#include "ui_qgsauthsaml2edit.h"


QgsAuthSAML2Edit::QgsAuthSAML2Edit( QWidget *parent )
    : QgsAuthMethodEdit( parent )
    , mValid( 0 )
{
  setupUi( this );
}

QgsAuthSAML2Edit::~QgsAuthSAML2Edit()
{
}

bool QgsAuthSAML2Edit::validateConfig()
{
  bool curvalid = !leUsername->text().isEmpty();
  if ( mValid != curvalid )
  {
    mValid = curvalid;
    emit validityChanged( curvalid );
  }
  return curvalid;
}

QgsStringMap QgsAuthSAML2Edit::configMap() const
{
  QgsStringMap config;
  config.insert( "username", leUsername->text() );
  config.insert( "password", lePassword->text() );

  return config;
}

void QgsAuthSAML2Edit::loadConfig( const QgsStringMap &configmap )
{
  clearConfig();

  mConfigMap = configmap;
  leUsername->setText( configmap.value( "username" ) );
  lePassword->setText( configmap.value( "password" ) );

  validateConfig();
}

void QgsAuthSAML2Edit::resetConfig()
{
  loadConfig( mConfigMap );
}

void QgsAuthSAML2Edit::clearConfig()
{
  leUsername->clear();
  lePassword->clear();
  leRealm->clear();
  chkPasswordShow->setChecked( false );
}

void QgsAuthSAML2Edit::on_leUsername_textChanged( const QString &txt )
{
  Q_UNUSED( txt );
  validateConfig();
}

void QgsAuthSAML2Edit::on_chkPasswordShow_stateChanged( int state )
{
  lePassword->setEchoMode(( state > 0 ) ? QLineEdit::Normal : QLineEdit::Password );
}
