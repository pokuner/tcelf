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
    __attribute__((section("class.counter"))) static int mycount_;
    char name_[12];
};
