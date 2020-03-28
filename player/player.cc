#include "player.h"
#include <string.h>

extern "C"
{
    IPlayer *create_player()
    {
        new CLotteryPlayer("p1");
        new CLotteryPlayer("p1");

        return new CPlayer("tom");
    }
}

unsigned long long CPlayer::mycount_ = 0;
unsigned long long CPlayer::myinfo_ = 0;

CPlayer::CPlayer(const char *name)
{
    myinfo_ = *(unsigned long long *)this;
    ++mycount_;
    strncpy(name_, name, sizeof(name_));
}

CPlayer::~CPlayer()
{
    if (mycount_ > 0)
        --mycount_;
}

const char *CPlayer::GetName() const
{
    return name_;
}

unsigned long long CLotteryPlayer::mycount_ = 0;
unsigned long long CLotteryPlayer::myinfo_ = 0;

CLotteryPlayer::CLotteryPlayer(const char *name)
    : CPlayer(name)
{
    myinfo_ = *(unsigned long long *)this;
    ++mycount_;
}

CLotteryPlayer::~CLotteryPlayer()
{
    if (mycount_ > 0)
        --mycount_;
}