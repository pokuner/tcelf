#include "player.h"
#include <string.h>

extern "C" {
IPlayer* create_player()
{
    return new CPlayer("tom");
}
}

int CPlayer::mycount_ = 0;

CPlayer::CPlayer(const char *name)
{
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