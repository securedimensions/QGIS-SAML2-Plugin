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


#ifndef QGSAUTHSAML2METHOD_H
#define QGSAUTHSAML2METHOD_H

#include "qgsauthconfig.h"
#include "qgsauthmethod.h"

class QgsAuthSAML2Method : public QgsAuthMethod
{
  Q_OBJECT

public:
  explicit QgsAuthSAML2Method();
  ~QgsAuthSAML2Method();
  // QgsAuthMethod interface
  QString key() const override;

  QString description() const override;

  QString displayDescription() const override;

  bool updateNetworkRequest( QNetworkRequest &request, const QString &authcfg,
    const QString &dataprovider = QString() ) override;

  bool updateNetworkReply( QNetworkReply *reply, const QString &authcfg,
    const QString &dataprovider ) override;

  bool updateDataSourceUriItems( QStringList &connectionItems, const QString &authcfg,
    const QString &dataprovider = QString() ) override;

  void clearCachedConfig( const QString &authcfg ) override;

  void updateMethodConfig( QgsAuthMethodConfig &mconfig ) override;


private:

  QgsAuthMethodConfig getMethodConfig( const QString &authcfg, bool fullconfig = true );

  void putMethodConfig( const QString &authcfg, const QgsAuthMethodConfig& mconfig );

  void removeMethodConfig( const QString &authcfg );

  static QMap<QString, QgsAuthMethodConfig> mAuthConfigCache;
};

#endif // QGSAUTHSAML2METHOD_H
