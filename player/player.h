#pragma once
#include "iplayer.h"

extern "C"
{
    IPlayer *create_player();
}

class CPlayer : public IPlayer
{
public:
    CPlayer(const char *name);
    virtual ~CPlayer();
    virtual const char *GetName() const;

private:
    __attribute__((section(".class.counter"))) static unsigned long long mycount_;
    __attribute__((section(".class.counter"))) static unsigned long long myinfo_;

    char name_[12];
};

class CLotteryPlayer : public CPlayer
{
public:
    CLotteryPlayer(const char *name);
    virtual ~CLotteryPlayer();

private:
    __attribute__((section(".class.counter"))) static unsigned long long mycount_;
    __attribute__((section(".class.counter"))) static unsigned long long myinfo_;
};
