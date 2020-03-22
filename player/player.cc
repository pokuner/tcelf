#include "player.h"
#include <string.h>

extern "C" {
IPlayer* create_player()
{
    return new CPlayer("tom");
}
}


CPlayer::CPlayer(const char *name)
{
    strncpy(name_, name, sizeof(name_));
}

CPlayer::~CPlayer()
{
}

const char *CPlayer::GetName() const
{
    return name_;
}