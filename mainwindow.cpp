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

    ui->outputTable->setColumnCount(8);
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
    headerItem = new QTableWidgetItem("");
    ui->outputTable->setHorizontalHeaderItem(7, headerItem);

    ui->tcpFlowOutput->setColumnCount(7);
    ui->tcpFlowOutput->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tcpFlowOutput->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tcpFlowOutput->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tcpFlowOutput->setAlternatingRowColors(true);

    headerItem = new QTableWidgetItem("时间");
    ui->tcpFlowOutput->setHorizontalHeaderItem(0, headerItem);
    headerItem = new QTableWidgetItem("包长度");
    ui->tcpFlowOutput->setHorizontalHeaderItem(1, headerItem);
    headerItem = new QTableWidgetItem("协议");
    ui->tcpFlowOutput->setHorizontalHeaderItem(2, headerItem);
    headerItem = new QTableWidgetItem("源地址");
    ui->tcpFlowOutput->setHorizontalHeaderItem(3, headerItem);
    headerItem = new QTableWidgetItem("目的地址");
    ui->tcpFlowOutput->setHorizontalHeaderItem(4, headerItem);
    headerItem = new QTableWidgetItem("源端口");
    ui->tcpFlowOutput->setHorizontalHeaderItem(5, headerItem);
    headerItem = new QTableWidgetItem("目的端口");
    ui->tcpFlowOutput->setHorizontalHeaderItem(6, headerItem);

    ui->rawData->setWordWrap(true);
    ui->rawData_2->setWordWrap(true);

    get_packet_thread = new Thread_GetPacket;

    this->setBuffPtr(get_packet_thread->getBuffPtr());
    this->setOffsetPtr(get_packet_thread->getOffsetPtr());

    QObject::connect(this, SIGNAL(SIG_controlGetPacket(bool, struct dev *, ProtoSel)), get_packet_thread, SLOT(controlGetPacket(bool, struct dev *, ProtoSel)));
    QObject::connect(get_packet_thread, SIGNAL(SIG_fillTable()), this, SLOT(fillTable()));
    QObject::connect(this, SIGNAL(SIG_fillTrackTable()), this, SLOT(fillTrackTable()));

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

void MainWindow::fillTrackTable() {
    struct parse_struct parse_res;
    while (track_offset < fill_offset && track_enable) {
        parseProtoHeader(buff[track_offset].data, &parse_res);
        bool flow = false;
        if (parse_res.TRANS_type == TRANS_TCP) {
            flow = true;
            if ( (parse_res.sport == track_port1 && parse_res.dport == track_port2) ) {
                for (int i = 0; i < 4; i++) {
                    if (parse_res.src_ip[i] != track_ip1[i]
                        || parse_res.dst_ip[i] != track_ip2[i]) {
                        flow = false;
                        break;
                    }
                }
            } else if ((parse_res.dport == track_port1 && parse_res.sport == track_port2)) {
                    for (int i = 0; i < 4; i++) {
                    if (parse_res.src_ip[i] != track_ip2[i]
                        || parse_res.dst_ip[i] != track_ip1[i]) {
                        flow = false;
                        break;
                    }
                }
            } else {
                flow = false;
            }
        }

        if (flow) {
            ui->tcpFlowOutput->insertRow(track_fill_offset);

            time_t local_tv_sec = buff[track_offset].header->ts.tv_sec;
            struct tm * ltime = localtime(&local_tv_sec);
            char timestr[16];
            strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

            parseProtoHeader(buff[track_offset].data, &parse_res);

            QTableWidgetItem *timestamp = new QTableWidgetItem(timestr);
            ui->tcpFlowOutput->setItem(track_fill_offset, 0, timestamp);

            QTableWidgetItem *length = new QTableWidgetItem(QString ::number(buff[track_offset].header->len));
            ui->tcpFlowOutput->setItem(track_fill_offset, 1, length);

            QTableWidgetItem * protocol;
            QTableWidgetItem * src_addr;
            QTableWidgetItem * dst_addr;
            QTableWidgetItem * sport;
            QTableWidgetItem * dport;

            if (parse_res.TRANS_type != TRANS_NONE) {
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
            }

            ui->tcpFlowOutput->setItem(track_fill_offset, 2, protocol);
            ui->tcpFlowOutput->setItem(track_fill_offset, 3, src_addr);
            ui->tcpFlowOutput->setItem(track_fill_offset, 4, dst_addr);
            ui->tcpFlowOutput->setItem(track_fill_offset, 5, sport);
            ui->tcpFlowOutput->setItem(track_fill_offset, 6, dport);
            track_fill_offset++;
        }

        track_offset++;
    }
}

void MainWindow::fillTable()
{
    while (fill_offset < *offset) {
        emit SIG_fillTrackTable();
        struct parse_struct parse_res;

        parseProtoHeader(buff[fill_offset].data, &parse_res);

        ui->outputTable->insertRow(fill_offset);

        time_t local_tv_sec = buff[fill_offset].header->ts.tv_sec;
		struct tm * ltime = localtime(&local_tv_sec);
		char timestr[16];
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

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
            } else if (parse_res.ETH_type == ETH_ARP_REPLY) {
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
        connect(ui->outputTable,SIGNAL(cellClicked(int, int)), this, SLOT(showRawData(int,int)));
        
        if (parse_res.TRANS_type == TRANS_TCP) {
            QPushButton *button = new QPushButton("跟踪");
            button->setProperty("id", fill_offset);
            connect(button, SIGNAL(clicked()), this, SLOT(trackTCP()));
            ui->outputTable->setCellWidget(fill_offset, 7, button);
        }


        fill_offset++;
    }

}

void MainWindow::trackTCP() {
    QPushButton *button = (QPushButton *)sender();
    int sender_row = button->property("id").toInt();

    if (current_track != sender_row) {
        ui->tcpFlowOutput->clearContents();
        track_fill_offset = 0;
        track_offset = 0;

        struct parse_struct parse_res;
        parseProtoHeader(buff[sender_row].data, &parse_res);
        memcpy(track_ip1, parse_res.src_ip, 4);
        memcpy(track_ip2, parse_res.dst_ip, 4);
        track_port1 = parse_res.sport;
        track_port2 = parse_res.dport;
    }

    current_track = sender_row;
    track_enable = 1;
    emit SIG_fillTrackTable();
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
    ui->protocolAnalyse->clear();

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


    ui->rawData->addItem(text1);
    ui->rawData_2->addItem(text2);

    struct parse_struct parse_res;
    parseProtoHeader(buff[row].data, &parse_res);

    // QString text3;
    if (parse_res.APP_type != APP_NONE) {
        ui->protocolAnalyse->addItem("Application layer: ");
        if (parse_res.APP_type == APP_HTTP) {
            ui->protocolAnalyse->addItem("    HTTP");
        } else if (parse_res.APP_type == APP_HTTPS) {
            ui->protocolAnalyse->addItem("    HTTPS");
        } else if (parse_res.APP_type == APP_SMTP) {
            ui->protocolAnalyse->addItem("    SMTP");
        } else if (parse_res.APP_type == APP_DNS) {
            ui->protocolAnalyse->addItem("    DNS");
            ui->protocolAnalyse->addItem("    ID: " + QString::number(parse_res.trans_ID));
            ui->protocolAnalyse->addItem("    flags: 0x" + QString::number(parse_res.flags, 16));     
            ui->protocolAnalyse->addItem("    question: " + QString::number(parse_res.question));
            ui->protocolAnalyse->addItem("    answer_RRs: " + QString::number(parse_res.answer_RRs));
            ui->protocolAnalyse->addItem("    Authority_RRs: " + QString::number(parse_res.Authority_RRs));
            ui->protocolAnalyse->addItem("    Additional_RRs: " + QString::number(parse_res.Additional_RRs));
               
        }
    }

    if (parse_res.TRANS_type != TRANS_NONE) {
        ui->protocolAnalyse->addItem("Transport Layer: ");
        if (parse_res.TRANS_type == TRANS_TCP) {
            ui->protocolAnalyse->addItem("    TCP");
            ui->protocolAnalyse->addItem("    source port: " + QString::number(parse_res.sport));
            ui->protocolAnalyse->addItem("    destination   port: " + QString::number(parse_res.dport) );
            ui->protocolAnalyse->addItem("    seq: " + QString::number(parse_res.seq));
            ui->protocolAnalyse->addItem("    ack: " + QString::number(parse_res.ack));
            ui->protocolAnalyse->addItem("    SYN: " + QString::number(parse_res.SYN));
            ui->protocolAnalyse->addItem("    FIN: " + QString::number(parse_res.FIN));
            ui->protocolAnalyse->addItem("    window size: " + QString::number(parse_res.wind_size));
            ui->protocolAnalyse->addItem("    check sum: " + QString::number(parse_res.check_sum));
        } else if (parse_res.TRANS_type == TRANS_UDP) {
            ui->protocolAnalyse->addItem("    UDP");
            ui->protocolAnalyse->addItem("    source port: " + QString::number(parse_res.sport));
            ui->protocolAnalyse->addItem("    destination   port: " + QString::number(parse_res.dport));
        }
    }

    if (parse_res.IP_type != IP_NONE) {
        ui->protocolAnalyse->addItem("Network Layer: ");
        if (parse_res.IP_type == IP_IP4) {
            ui->protocolAnalyse->addItem("    protocol: IPv4");
            ui->protocolAnalyse->addItem("    source IP: " + getAddrStr((char*)parse_res.src_ip, 4, 10));
            ui->protocolAnalyse->addItem("    destination IP: " + getAddrStr((char*)parse_res.dst_ip, 4, 10));
            ui->protocolAnalyse->addItem("    length: " + QString::number(parse_res.ip_len));
            ui->protocolAnalyse->addItem("    ttl: " + QString::number(parse_res.ttl));
        } else if (parse_res.IP_type == IP_IP6) {
            ui->protocolAnalyse->addItem("    protocol: IPv4\n");
            ui->protocolAnalyse->addItem("    source IP: " + getAddrStr((char*)parse_res.src_ip, 4, 10));
            ui->protocolAnalyse->addItem("    destination IP: " + getAddrStr((char*)parse_res.dst_ip, 4, 10));
            ui->protocolAnalyse->addItem("    length: " + QString::number(parse_res.ip_len));
        } else if (parse_res.IP_type == IP_ICMP) {
            ui->protocolAnalyse->addItem("    protocol: ICMP");
            ui->protocolAnalyse->addItem("    source IP: " + getAddrStr((char*)parse_res.src_ip, 4, 10));
            ui->protocolAnalyse->addItem("    destination IP: " + getAddrStr((char*)parse_res.dst_ip, 4, 10));
            ui->protocolAnalyse->addItem("    length: " + QString::number(parse_res.ip_len));
            QString text;
            text.append("    icmp type: ");
            switch (parse_res.icmp_type)
            {
            case ICMP_PING_REQ:
                text.append("PING req");
                break;
            case ICMP_PING_RLY:
               text.append("PING reply");
                break;
            case ICMP_HOST_UA:
                text.append("host unreachable");
                break;
            case ICMP_NET_UA:
                text.append("net unreachable");
                break;
            case ICMP_TIMEOUT:
                text.append("timeout");
                break;
            default:
                break;
            }

            text.append(" (type field: " + QString::number(parse_res.icmp_type_int));
            text.append(", code field: " + QString::number(parse_res.icmp_code_int) + ")");
            ui->protocolAnalyse->addItem(text);
        }
    }

    ui->protocolAnalyse->addItem("Link layer:");
    if (parse_res.ETH_type == ETH_ARP) {

        QString text;
        text.append("    hardware type: ");
        if (parse_res.hardware_type == 1) {
            text.append("Ethernet");
        } else {
            text.append("Unknow");
        }
        text.append(" (0x" + QString::number(parse_res.hardware_type) + ")");
        ui->protocolAnalyse->addItem(text);

        text.clear();
        text.append("    resolved protocol type: ");
        if (parse_res.proto_type == 0x0800) {
            text.append("IP");
        } else {
            text.append("Unknow");
        }
        text.append(" (" + QString::number(parse_res.proto_type, 16) + ")");
        ui->protocolAnalyse->addItem(text);

        text.clear();
        text.append("    operation: ");
        switch (parse_res.op_code)
        {
        case CODE_ARP_REQ:
            text.append("ARP request");
            break;
        case CODE_ARP_RLY:
            text.append("ARP reply");
            break;
        case CODE_ARP_RARP_REQ:
            text.append("RARP request");
            break;
        case CODE_ARP_RARP_RLY:
            text.append("RARP reply");
        }
        text.append(" ("+ QString::number(parse_res.op_code) + ")");

        ui->protocolAnalyse->addItem("    source mac address:  " + getAddrStr((char*)parse_res.arp_src_mac, 6, 16));
        ui->protocolAnalyse->addItem("    destination mac address:  " + getAddrStr((char*)parse_res.arp_dst_mac, 6, 16));
        ui->protocolAnalyse->addItem("    source ip address:  " + getAddrStr((char*)parse_res.arp_src_ip, 4, 10));
        ui->protocolAnalyse->addItem("    destination ip address:  " + getAddrStr((char*)parse_res.arp_dst_ip, 4, 10));
    } else {
        ui->protocolAnalyse->addItem("    source mac address:  " + getAddrStr((char*)parse_res.src_mac, 6, 16));
        ui->protocolAnalyse->addItem("    destination mac address:  " + getAddrStr((char*)parse_res.dst_mac, 6, 16));
    }

    // ui->protocolAnalyse->addItem(text3);
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

void MainWindow::on_stopTrack_clicked()
{
    track_enable = 0;
}
