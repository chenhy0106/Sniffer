#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QStandardItemModel>
#include "sniffer_back.h"
#include "qthread.h"
#include <iostream>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent),
                                          ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    initDevList();
    current_state = STOP;

    ui->outputTable->setColumnCount(2);

    get_packet_thread = new Thread_GetPacket;

    this->setBuffPtr(get_packet_thread->getBuffPtr());
    this->setOffsetPtr(get_packet_thread->getOffsetPtr());

    QObject::connect(this, SIGNAL(SIG_controlGetPacket(bool, char *)), get_packet_thread, SLOT(controlGetPacket(bool, char*)));
    QObject::connect(get_packet_thread, SIGNAL(SIG_fillTable()), this, SLOT(fillTable()));

    get_packet_thread->start();
}

MainWindow::~MainWindow()
{
    delete ui;
    delete get_packet_thread;
    freeDevList(devList, dev_count);
}

void MainWindow::initDevList()
{
    ui->stateDisplay->setText("Detect adapter……");

    LoadNpcapDlls();

    getDevList(&devList, &dev_count);

    for (int i = 0; i < dev_count; i++)
    {
        ui->devSelector->addItem(QString::asprintf("%s", devList[i].description));
    }

    ui->stateDisplay->setText("Ready");
    current_state = STOP;
}

void MainWindow::on_startButton_clicked()
{
    if (current_state == RUN)
    {
        if (current_dev != last_dev) {
            ui->stateDisplay->setText("Stop current processing before start another one");
        }

        return;
    }

    if (current_dev != last_dev) {
        // TODO: reset table
        // fill_offset = 0;
    }

    last_dev = current_dev;
    current_dev = ui->devSelector->currentIndex();

    ui->stateDisplay->setText(QString::asprintf("Running (Adapter: %s)", devList[current_dev].description));

    current_state = RUN;

    emit SIG_controlGetPacket(START_GETPACKET, devList[current_dev].name);
}

void MainWindow::on_endButton_clicked()
{
    if (current_state == STOP) {
        return;
    }

    current_state = STOP;
    ui->stateDisplay->setText("Stop");

    emit SIG_controlGetPacket(STOP_GETPACKET, devList[current_dev].name);
}

void MainWindow::fillTable()
{
    while (fill_offset <= *offset) {
        
        time_t local_tv_sec = buff[fill_offset].header->ts.tv_sec;
		struct tm * ltime = localtime(&local_tv_sec);
		char timestr[16];
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		
        ui->outputTable->insertRow(fill_offset);
        QTableWidgetItem *timestamp = new QTableWidgetItem(timestr);
        ui->outputTable->setItem(fill_offset, 0, timestamp);
        QTableWidgetItem *length = new QTableWidgetItem(QString ::number(buff[fill_offset].header->len));
        ui->outputTable->setItem(fill_offset, 1, length);

        fill_offset++;
    }
}

Thread_GetPacket::Thread_GetPacket() {
    buff = new struct packet [MAX_BUFF_NO];
}

Thread_GetPacket::~Thread_GetPacket() {
    delete buff;
}

void Thread_GetPacket::run() {
    while (1) {
        while (state == RUN && buff_offset != buff_size) {
            std::cout << "get packet thread run\n";
            int read_packet = getPackets(buff, buff_offset, target_name, PACHKET_PER_BUFF, 5, 0, 0);
            if (read_packet == -1) {
                state = STOP;
            } else if (read_packet != 0) {
                buff_offset += read_packet;
                emit SIG_fillTable();
            }    
        }
    }
}

void Thread_GetPacket::controlGetPacket(bool control, char * new_dev_name) {
    if (control == START_GETPACKET) {
        if (new_dev_name != target_name) {
            buff_offset = 0;
            target_name = new_dev_name;
        }

        state = RUN;
    } else {
        state = STOP;
    }
}
