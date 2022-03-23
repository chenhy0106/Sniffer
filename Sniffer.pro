#-------------------------------------------------
#
# Project created by QtCreator 2022-03-19T20:15:18
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Sniffer
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
        sniffer_back.c \
        proto.c

HEADERS += \
        mainwindow.h \
        sniffer_back.h \
        proto.h

FORMS += \
        mainwindow.ui



INCLUDEPATH += E:/UCAS/secure/sniffer/npcap-sdk-1.12/Include
LIBS += -LE:\UCAS\secure\sniffer\npcap-sdk-1.12\Lib -lwpcap
