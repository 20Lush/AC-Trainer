#include <windows.h>

struct ACPlayer {

    FLOAT   xheadPosition;                                       // +0x004
    FLOAT   yheadPosition;                                       // +0x008
    FLOAT   zheadPosition;                                       // +0x00C 
    FLOAT   xVelocity;                                           // +0x01C 
    FLOAT   yVelocity;                                           // +0x020
    FLOAT   zVelocity;                                           // +0x024
    FLOAT   xfeetPosition;                                       // +0x028
    FLOAT   yfeetPosition;                                       // +0x02C
    FLOAT   zfeetPosition;                                       // +0x030 
    FLOAT   xView;                                               // +0x034
    FLOAT   yView;                                               // +0x038
    FLOAT   zView;                                               // +0x03C 
    INT32   jumpFallSpeed;                                       // +0x048 
    FLOAT   originCurrHeight;                                    // +0x050 
    FLOAT   originSetHeight;                                     // +0x054 
    INT32   isOnGround;                                          // +0x05D 
    INT32   isCrouched;                                          // +0x063 
    INT32   isImmobile;                                          // +0x065 
    INT8    inputDirection;                                      // +0x074 
    FLOAT   crouchVel;                                           // +0x078 
    INT32   health;                                              // +0x0EC 
    INT32   armor;                                               // +0x0F0 
    INT8    dualPistolEnabled;                                   // +0x100 
    INT32   pistolReserveAmmo;                                   // +0x108 
    INT32   carbineReserveAmmo;                                  // +0x10C 
    INT32   shotgunReserveAmmo;                                  // +0x110 
    INT32   smgReserveAmmo;                                      // +0x114 
    INT32   snipeReserveAmmo;                                    // +0x118 
    INT32   arReserveAmmo;                                       // +0x11C 
    INT32   dualPistolReserveAmmo;                               // +0x124 
    INT32   pistolLoadedAmmo;                                    // +0x12C 
    INT32   carbineLoadedAmmo;                                   // +0x130 
    INT32   loadedShotgunAmmo;                                   // +0x134 
    INT32   smgLoadedAmmo;                                       // +0x138 
    INT32   sniperLoadedAmmo;                                    // +0x13C 
    INT32   arLoadedAmmo;                                        // +0x140 
    INT32   grenades;                                            // +0x144 
    INT32   dualPistolLoadedAmmo;                                // +0x148 
    INT32   knifeSlashDelay;                                     // +0x14C 
    INT32   pistolShootDelay;                                    // +0x150 
    INT32   carabineShootDelay;                                  // +0x154 
    INT32   shotgunShotDelay;                                    // +0x158 
    INT32   smgShootDelay;                                       // +0x15C 
    INT32   sniperRifleShootDelay;                               // +0x160 
    INT32   assaultRifleShootDelay;                              // +0x164 
    INT32   dualPistolShootDelay;                                // +0x16C 
    INT32   numberOfDeaths;                                      // +0x1E4 
    CHAR    nickname;                                            // +0x205 
    INT8    team;                                                // +0x30C 

};