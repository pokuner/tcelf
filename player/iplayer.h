#pragma once

class IPlayer
{
public:
    virtual ~IPlayer() = 0;
    virtual const char *GetName() const = 0;
};
