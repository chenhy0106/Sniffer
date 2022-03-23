#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>

#include "sniffer_back.h"


#define MAX_BUFF_NO 65536
#define PACHKET_PER_BUFF 16

#define START_GETPACKET 0
#define STOP_GETPACKET 1


namespace Ui {
class MainWindow;
}

enum state_set {RUN, STOP};

class Thread_GetPacket : public QThread {
    Q_OBJECT
private:
    //线程退出的标识量
    volatile std::atomic<state_set> state;
    struct packet *                 buff = NULL;
    std::atomic<unsigned>           buff_offset;
    unsigned                        buff_size = MAX_BUFF_NO;
    struct dev *                    target_dev = NULL;
    ProtoSel                        proto_sel;

protected:
    void run();
public:
    Thread_GetPacket();
    ~Thread_GetPacket();

    struct packet * getBuffPtr() {return buff;}
    std::atomic<unsigned> * getOffsetPtr() {return &buff_offset;}
public slots:
    void controlGetPacket(bool control, struct dev * new_dev, ProtoSel protosel);

signals:
    void SIG_fillTable();
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    void setBuffPtr(struct packet * buff_ptr) {buff = buff_ptr;}
    void setOffsetPtr(std::atomic<unsigned>* offset_ptr) {offset = offset_ptr;}

public slots:
    void on_startButton_clicked();
    void on_endButton_clicked();

    void fillTable();


signals:
    void SIG_controlGetPacket(bool control, struct dev * new_dev, ProtoSel protosel);

private:
    Ui::MainWindow  *   ui;

    Thread_GetPacket * get_packet_thread;

    state_set           current_state = STOP;
    ProtoSel            current_proto = SEL_ALL;

    struct dev      *   devList = NULL;
    int                 dev_count = 0;
    int                 current_dev = 0;
    int                 last_dev = -1;
    ProtoSel            current_sel = SEL_ALL;
    ProtoSel            last_sel = SEL_ALL;

    unsigned            fill_offset = 0;
    struct packet   *   buff;
    std::atomic<unsigned>*   offset;


    void initDevList();
    QString getAddrStr(char * addr, int len, int base);

};

#endif // MAINWINDOW_H
