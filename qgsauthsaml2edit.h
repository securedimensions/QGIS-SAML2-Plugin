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


#ifndef QGSAUTHSAML2EDIT_H
#define QGSAUTHSAML2EDIT_H

#include <QWidget>
#include "qgsauthmethodedit.h"
#include "ui_qgsauthsaml2edit.h"

#include "qgsauthconfig.h"


class QgsAuthSAML2Edit : public QgsAuthMethodEdit, private Ui::QgsAuthSAML2Edit
{
  Q_OBJECT

public:
  explicit QgsAuthSAML2Edit( QWidget *parent = nullptr );
  virtual ~QgsAuthSAML2Edit();

  bool validateConfig() override;

  QgsStringMap configMap() const override;

public slots:
  void loadConfig( const QgsStringMap &configmap ) override;

  void resetConfig() override;

  void clearConfig() override;

private slots:
  void on_leUsername_textChanged( const QString& txt );

  void on_chkPasswordShow_stateChanged( int state );

  void onFedUrlChanged( const QString& url );

  void loadFederationMetadata();

  void parseFederationMetadata();



private:
  QgsStringMap mConfigMap;
  bool mValid;
  void setupConnections();
};

#endif // QGSAUTHSAML2EDIT_H
