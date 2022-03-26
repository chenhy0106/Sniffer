#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QStandardItemModel>
#include "sniffer_back.h"
#include <QThread>
#include "proto.h"
#include <iostream>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent),
                                          ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    initDevList();
    current_state = STOP;

    ui->outputTable->setColumnCount(7);
    ui->outputTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->outputTable->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->outputTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->outputTable->setAlternatingRowColors(true);

    QTableWidgetItem * headerItem = new QTableWidgetItem("时间");
    ui->outputTable->setHorizontalHeaderItem(0, headerItem);
    headerItem = new QTableWidgetItem("包长度");
    ui->outputTable->setHorizontalHeaderItem(1, headerItem);
    headerItem = new QTableWidgetItem("协议");
    ui->outputTable->setHorizontalHeaderItem(2, headerItem);
    headerItem = new QTableWidgetItem("源地址");
    ui->outputTable->setHorizontalHeaderItem(3, headerItem);
    headerItem = new QTableWidgetItem("目的地址");
    ui->outputTable->setHorizontalHeaderItem(4, headerItem);
    headerItem = new QTableWidgetItem("源端口");
    ui->outputTable->setHorizontalHeaderItem(5, headerItem);
    headerItem = new QTableWidgetItem("目的端口");
    ui->outputTable->setHorizontalHeaderItem(6, headerItem);

    ui->rawData->setWordWrap(true);
    ui->rawData_2->setWordWrap(true);


    get_packet_thread = new Thread_GetPacket;

    this->setBuffPtr(get_packet_thread->getBuffPtr());
    this->setOffsetPtr(get_packet_thread->getOffsetPtr());

    QObject::connect(this, SIGNAL(SIG_controlGetPacket(bool, struct dev *, ProtoSel)), get_packet_thread, SLOT(controlGetPacket(bool, struct dev *, ProtoSel)));
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
    current_proto = SEL_ALL;
}

void MainWindow::on_startButton_clicked()
{
    if (current_state == RUN)
    {
        if (current_dev != last_dev) {
            ui->stateDisplay->setText("Stop current processing before start another one");
            return;
        }
    }

    // if (current_dev != last_dev) {
    //     // TODO: reset table
    //     fill_offset = 0;
    //     ui->outputTable->clearContents();
    // }

    last_dev = current_dev;
    current_dev = ui->devSelector->currentIndex();

    ui->stateDisplay->setText(QString::asprintf("Running (Adapter: %s)", devList[current_dev].description));

    current_state = RUN;
    current_proto = ProtoSel(ui->protoSelector->currentIndex());

    emit SIG_controlGetPacket(START_GETPACKET, &devList[current_dev], current_proto);
}

void MainWindow::on_endButton_clicked()
{
    if (current_state == STOP) {
        return;
    }

    current_state = STOP;
    ui->stateDisplay->setText("Stop");

    emit SIG_controlGetPacket(STOP_GETPACKET, &devList[current_dev], current_proto);
}

void MainWindow::fillTable()
{
    while (fill_offset < *offset) {
        ui->outputTable->insertRow(fill_offset);

        time_t local_tv_sec = buff[fill_offset].header->ts.tv_sec;
		struct tm * ltime = localtime(&local_tv_sec);
		char timestr[16];
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
        struct parse_struct parse_res;
        parseProtoHeader(buff[fill_offset].data, &parse_res);

        QTableWidgetItem *timestamp = new QTableWidgetItem(timestr);
        ui->outputTable->setItem(fill_offset, 0, timestamp);

        QTableWidgetItem *length = new QTableWidgetItem(QString ::number(buff[fill_offset].header->len));
        ui->outputTable->setItem(fill_offset, 1, length);

        QTableWidgetItem * protocol;
        QTableWidgetItem * src_addr;
        QTableWidgetItem * dst_addr;
        QTableWidgetItem * sport;
        QTableWidgetItem * dport;

        if (parse_res.APP_type != APP_NONE && (current_proto <= SEL_SMTP)) {
            if (parse_res.APP_type == APP_DNS) {
                protocol = new QTableWidgetItem("DNS"); 
            } else if (parse_res.APP_type == APP_HTTP) {
                protocol = new QTableWidgetItem("HTTP"); 
            } else if (parse_res.APP_type == APP_HTTPS) {
                protocol = new QTableWidgetItem("HTTPS"); 
            } else if (parse_res.APP_type == APP_SMTP) {
                protocol = new QTableWidgetItem("SMTP"); 
            } else {
                protocol = new QTableWidgetItem("unknow (app)"); 
            }

            sport = new QTableWidgetItem(QString::number(parse_res.sport));
            dport = new QTableWidgetItem(QString::number(parse_res.dport));

            if (parse_res.IP_type == IP_IP6) {
                src_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.src_ip, 16, 16));
                dst_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.dst_ip, 16, 16));
            } else {
                src_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.src_ip, 4, 10));
                dst_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.dst_ip, 4, 10));
            }

        } else if (parse_res.TRANS_type != TRANS_NONE && current_proto <= SEL_UDP) {
            if (parse_res.TRANS_type == TRANS_TCP) {
                protocol = new QTableWidgetItem("TCP"); 
            } else if (parse_res.TRANS_type == TRANS_UDP) {
                protocol = new QTableWidgetItem("UDP");
            } else {
                protocol = new QTableWidgetItem("UNKNOW (trans)");
            }

            sport = new QTableWidgetItem(QString::number(parse_res.sport));
                dport = new QTableWidgetItem(QString::number(parse_res.dport));

            if (parse_res.IP_type == IP_IP6) {
                src_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.src_ip, 16, 16));
                dst_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.dst_ip, 16, 16));
            } else {
                src_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.src_ip, 4, 10));
                dst_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.dst_ip, 4, 10));
            }
        } else if (parse_res.IP_type != IP_NONE && current_proto <= SEL_IPV6) {
            if (parse_res.IP_type == IP_ICMP) {
                protocol = new QTableWidgetItem("ICMP"); 
            } else if (parse_res.IP_type == IP_IP4) {
                protocol = new QTableWidgetItem("IPv4"); 
            } else if (parse_res.IP_type == IP_IP6) {
                protocol = new QTableWidgetItem("IPv6"); 
            } else {
                protocol = new QTableWidgetItem("UNKNOW (ip)"); 
            }

            if (parse_res.IP_type == IP_IP6) {
                src_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.src_ip, 16, 16));
                dst_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.dst_ip, 16, 16));
            } else {
                src_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.src_ip, 4, 10));
                dst_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.dst_ip, 4, 10));
            }

            sport = new QTableWidgetItem("");
            dport = new QTableWidgetItem("");
        } else {
            if (parse_res.ETH_type == ETH_ARP) {
                protocol = new QTableWidgetItem("ARP"); 
            } else if (parse_res.ETH_type == ETH_ARP_REPLAY) {
                protocol = new QTableWidgetItem("ARP Reply");
            } else {
                protocol = new QTableWidgetItem("UNKNOW (eth)");
            }

            src_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.src_mac, 6, 16));
            dst_addr = new QTableWidgetItem(getAddrStr((char*)parse_res.dst_mac, 6, 16));
            sport = new QTableWidgetItem("");
            dport = new QTableWidgetItem("");
        } 

        ui->outputTable->setItem(fill_offset, 2, protocol);
        ui->outputTable->setItem(fill_offset, 3, src_addr);
        ui->outputTable->setItem(fill_offset, 4, dst_addr);
        ui->outputTable->setItem(fill_offset, 5, sport);
        ui->outputTable->setItem(fill_offset, 6, dport);

        // ui->outputTable->scrollToBottom();

        connect(ui->outputTable,SIGNAL(cellClicked(int, int)), this, SLOT(showRawData(int,int)));

        
        fill_offset++;
    }
}

QString MainWindow::getAddrStr(char * addr, int len, int base) {
    QString res;
    int i = 0;

    while (i < (len - 1)) {
        res.append(QString::number((uint8_t)addr[i], base));
        res.append(":");
        i++;
    }
    res.append(QString::number((uint8_t)addr[i], base));
    
    return res;
}

void MainWindow::showRawData(int row, int col) {
    ui->rawData->clear();
    ui->rawData_2->clear();

    QString text1;
    QString text2;
    int len = buff[row].header->len;

    for (int i = 0; i < len; i++) {
        // text.append(QString::number((uint8_t)(buff[row].data[i]), 16));
        text1.append(QString::asprintf("%02x", (uint8_t)(buff[row].data[i])));
        text1.append(" ");

        char byte = buff[row].data[i];
        if (isgraph(byte)) {
            text2.append(byte);
        } else {
            text2.append(".");
        }
        text2.append(" ");
        
    }

    QListWidgetItem *item1 = new QListWidgetItem(text1);
    ui->rawData->addItem(item1);

    QListWidgetItem *item2 = new QListWidgetItem(text2);
    ui->rawData_2->addItem(item2);
}

Thread_GetPacket::Thread_GetPacket() {
    buff = new struct packet [MAX_BUFF_NO];
    state = STOP;
    buff_offset = 0;
}

Thread_GetPacket::~Thread_GetPacket() {
    deleteBuff(buff, buff_offset);
    delete buff;
}

void Thread_GetPacket::run() {
    while (1) {
        int packet_per_round = 4;
        if (proto_sel == SEL_ICMP || proto_sel == SEL_DNS || proto_sel == SEL_SMTP) {
            packet_per_round = 1;
        }
        while (state.load(std::memory_order_acquire) == RUN && buff_offset <= buff_size) {
            int read_packet = getPackets(buff, buff_offset, target_dev, packet_per_round, 5, proto_sel, 1);
            if (read_packet == -1) {
                state = STOP;
            } else if (read_packet != 0) {
                buff_offset += read_packet;
                emit SIG_fillTable();
            }    
        }
    }
}

void Thread_GetPacket::controlGetPacket(bool control, struct dev * new_dev, ProtoSel protosel) {
    if (control == START_GETPACKET) {
        target_dev = new_dev;
        proto_sel = protosel;
        state.store(RUN, std::memory_order_release);
    } else {
        state = STOP;
    }
}
