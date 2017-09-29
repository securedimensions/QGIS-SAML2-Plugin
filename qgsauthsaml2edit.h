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

  private:
    QgsStringMap mConfigMap;
    bool mValid;
};

#endif // QGSAUTHSAML2EDIT_H
