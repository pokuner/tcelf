#pragma once
#include "iplayer.h"

extern "C" {
    IPlayer* create_player();
}

class CPlayer : public IPlayer
{
public:
    CPlayer(const char *name);
    virtual ~CPlayer();
    virtual const char *GetName() const;

private:
    char name_[12];
};
