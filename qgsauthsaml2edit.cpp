/***************************************************************************
begin                : October 15, 2017
copyright            : (C) 2017 by Secure Dimensions GmbH, Germany
author               : Andreas Matheus, Secure Dimensions GmbH
email                : am at secure-dimensions dot de
***************************************************************************
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) any later version.                                   *
*                                                                         *
***************************************************************************/


#include <QStandardItemModel>
#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QXmlStreamReader>
#include <QMessageBox>

#include "qgsauthsaml2edit.h"
#include "ui_qgsauthsaml2edit.h"
#include "qgslogger.h"

QgsAuthSAML2Edit::QgsAuthSAML2Edit( QWidget *parent )
  : QgsAuthMethodEdit( parent )
  , mValid( 0 )
{
  setupUi( this );
  setupConnections();
}

QgsAuthSAML2Edit::~QgsAuthSAML2Edit()
{
}

bool QgsAuthSAML2Edit::validateConfig()
{
  bool curvalid = !leUsername->text().isEmpty() && !lePassword->text().isEmpty()
    && !leFedUrl->text().isEmpty() && cbProviders->currentIndex() != -1;
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
  config.insert( "federationurl", leFedUrl->text() );
  config.insert( "providername", cbProviders->currentText() );
  config.insert( "providerurl", cbProviders->itemData( cbProviders->currentIndex() ).toString() );

  return config;
}

void QgsAuthSAML2Edit::loadConfig( const QgsStringMap &configmap )
{
  clearConfig();

  mConfigMap = configmap;
  leUsername->setText( configmap.value( "username" ) );
  lePassword->setText( configmap.value( "password" ) );
  leFedUrl->setText( configmap.value( "federationurl" ) );
  cbProviders->clear();
  cbProviders->addItem( configmap.value( "providername" ), configmap.value( "providerurl" ) );

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
  chkPasswordShow->setChecked( false );
  leFedUrl->clear();
  cbProviders->clear();
  //btnGetProviders->setEnabled(false);
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

void QgsAuthSAML2Edit::setupConnections()
{
  connect( leFedUrl, SIGNAL( textChanged( const QString& ) ), 
    this, SLOT( onFedUrlChanged( const QString& ) ) );
  connect( btnGetProviders, SIGNAL ( clicked() ), 
    this, SLOT( loadFederationMetadata() ) );
}

void QgsAuthSAML2Edit::onFedUrlChanged( const QString& url )
{
  QUrl fedUrl(url);

  btnGetProviders->setEnabled( fedUrl.isValid() );

}

void QgsAuthSAML2Edit::loadFederationMetadata()
{
  // clear the list lof loaded IdPs
  cbProviders->clear();

  // load the federation metadata
  QNetworkAccessManager *manager = new QNetworkAccessManager( this );
  QNetworkReply* reply = manager->get( QNetworkRequest( QUrl(leFedUrl->text()) ) );
  // signal to parse the federation metadata upon load finished
  connect(reply, SIGNAL(finished()), this, SLOT(parseFederationMetadata()));
}

void QgsAuthSAML2Edit::parseFederationMetadata()
{  
  /* QXmlStreamReader takes any QIODevice. */
  QNetworkReply *reply = qobject_cast<QNetworkReply *>(sender());
  QXmlStreamReader xml(reply);

  QString entityID = QString();
  bool entityIsIdP = false;
  QString displayName = QString();
  QString ecpURL = QString();

  /* We'll parse the XML until we reach end of it.*/
  while(!xml.atEnd() &&!xml.hasError())
  {
    /* Read next element.*/
    QXmlStreamReader::TokenType token = xml.readNext();
    /* If token is just StartDocument, we'll go to next.*/
    if(token == QXmlStreamReader::StartDocument)
    {
      continue;
    }
    /* If token is StartElement, we'll see if we can read it.*/
    if(token == QXmlStreamReader::StartElement)
    {
      if(xml.name() == "EntitiesDescriptor")
      {
        continue;
      }
      if(xml.name() == "EntityDescriptor")
      {
        entityIsIdP = false;
        entityID = QString();
        displayName = QString();
        ecpURL = QString();

        QXmlStreamAttributes attrs = xml.attributes();
        entityID = QString(attrs.value("entityID").toString().constData());
        continue;
      }
      else if(xml.name() == "IDPSSODescriptor")
      {
        entityIsIdP = true;
        continue;
      }
      else if(xml.name() == "SingleSignOnService")
      {
        QXmlStreamAttributes attrs = xml.attributes();
        if (entityIsIdP && attrs.value("Binding") == QString("urn:oasis:names:tc:SAML:2.0:bindings:SOAP"))
        {
          ecpURL = QString(attrs.value("Location").toString().constData());
        }
        continue;
      }
      else if(xml.name() == "DisplayName")
      {
        if (entityIsIdP)
          displayName = QString(xml.readElementText().constData());

        continue;
      }

    }
    if(token == QXmlStreamReader::EndElement) 
    {
      if(xml.name() == "EntityDescriptor")
      {
        if(entityIsIdP && !ecpURL.isEmpty())
        {
          if (displayName.isEmpty())
            displayName = entityID;

          cbProviders->addItem(displayName,QVariant(ecpURL));

          QgsDebugMsg(QString("IdP entityID: %1").arg(entityID.toStdString().c_str()));
          QgsDebugMsg(QString("ECPURL: %1\n").arg( ecpURL.toStdString().c_str()));
          QgsDebugMsg(QString("Display Name: %1\n").arg( displayName.toStdString().c_str()));
        }
        continue;
      }
    }

  }
  /* Error handling. */
  if(xml.hasError()) 
  {
    QMessageBox::critical(this, 
      "error loading Federation Metadata", 
      xml.errorString(), 
      QMessageBox::Ok);
  }
  xml.clear();
  cbProviders->showPopup();
  reply->deleteLater();
}
