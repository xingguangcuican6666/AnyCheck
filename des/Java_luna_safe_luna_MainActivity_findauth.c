
uint Java_luna_safe_luna_MainActivity_findauth(void)

{
  uint uVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  int unaff_w20;
  byte unaff_w22;
  int unaff_w27;
  byte unaff_w28;
  byte local_9c;
  uint local_98;
  int local_94;
  char *local_90;
  char **local_88;
  char *local_80;
  char local_76;
  char local_75;
  byte local_74;
  int local_70;
  byte local_6c;
  byte local_68;
  int local_64;
  
  local_94 = 0;
  local_88 = &local_90;
  local_90 = &DAT_0013ffa0;
  do {
    iVar3 = 0x36d36be7;
    do {
      while( true ) {
        while( true ) {
          while( true ) {
            while (iVar4 = iVar3, iVar3 = iVar4, -0xd823239 < iVar4) {
              if (iVar4 < 0x495eea98) {
                if (iVar4 < 0x15b7e1a1) {
                  if (iVar4 == -0xd823238) {
                    uVar1 = (x.600 + -1) * x.600;
                    bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                    iVar3 = 0x173d1959;
                    if ((y.601 >= 10 || !bVar2) && y.601 < 10 == bVar2) {
                      iVar3 = 0x6c46074c;
                    }
                  }
                  else if (iVar4 == -0x562c3b9) {
                    local_98 = 0;
                    iVar3 = 0x15b7e1a1;
                  }
                }
                else if (iVar4 == 0x173d1959) {
                  bVar2 = ((x.600 + -1) * x.600 & 1U) == 0;
                  iVar3 = -0x562c3b9;
                  if ((y.601 >= 10 || !bVar2) && y.601 < 10 == bVar2) {
                    iVar3 = 0x6c46074c;
                  }
                }
                else if (iVar4 == 0x36d36be7) {
                  local_70 = local_94;
                  local_74 = local_9c;
                  iVar3 = -0x261258ed;
                  if (0 < local_94) {
                    iVar3 = 0x53187c1c;
                  }
                }
                else if (iVar4 == 0x15b7e1a1) {
                  return local_98;
                }
              }
              else if (iVar4 < 0x5e3728b4) {
                if (iVar4 == 0x495eea98) {
                  __android_log_print(4,&DAT_0013f18c,&DAT_0013ffe0,local_80);
                  unaff_w20 = 0;
                  iVar3 = 0x5e3728b4;
                  unaff_w28 = local_74;
                }
                else if (iVar4 == 0x53187c1c) {
                  iVar3 = -0x7ed9f9ba;
                  unaff_w22 = local_74;
                  unaff_w27 = 2;
                }
              }
              else if (iVar4 == 0x5e3728b4) {
                local_6c = unaff_w28;
                iVar3 = -0x31371113;
                unaff_w22 = unaff_w28;
                unaff_w27 = unaff_w20;
                if (unaff_w20 != 0) {
                  iVar3 = -0x7ed9f9ba;
                }
              }
              else {
                iVar3 = 0x173d1959;
                if ((iVar4 != 0x6c46074c) && (iVar3 = iVar4, iVar4 == 0x78b87cc6)) {
                  local_75 = local_64 == 2;
                  uVar1 = (x.600 + -1) * x.600;
                  bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
                  iVar3 = -0x791b0f3c;
                  if (y.601 < 10 == bVar2 && (9 < y.601 || !bVar2)) {
                    iVar3 = -0x152ff5a5;
                  }
                }
              }
            }
            if (-0x4b7ea83d < iVar4) break;
            if (iVar4 < -0x6974ac88) {
              if (iVar4 == -0x7ed9f9ba) {
                uVar1 = (x.600 + -1) * x.600 & 1;
                local_68 = unaff_w22;
                local_64 = unaff_w27;
                iVar3 = 0x78b87cc6;
                if (9 < y.601 == uVar1 && (9 < y.601 | uVar1) == 1) {
                  iVar3 = -0x152ff5a5;
                }
              }
              else if (iVar4 == -0x791b0f3c) {
                local_98 = (uint)local_68;
                iVar3 = -0xd823238;
                if (local_75 == '\0') {
                  iVar3 = 0x15b7e1a1;
                }
              }
            }
            else if (iVar4 == -0x6974ac88) {
              access(local_90,0);
              iVar3 = -0x2b9597ab;
            }
            else if (iVar4 == -0x66867abe) {
              iVar3 = -0x4b7ea83c;
              if (local_76 == '\0') {
                iVar3 = 0x495eea98;
              }
            }
          }
          if (iVar4 < -0x2b9597ab) break;
          if (iVar4 == -0x2b9597ab) {
            local_80 = local_90;
            iVar3 = access(local_90,0);
            local_76 = iVar3 == 0;
            bVar2 = ((x.600 + -1) * x.600 & 1U) == 0;
            iVar3 = -0x66867abe;
            if ((y.601 >= 10 || !bVar2) && y.601 < 10 == bVar2) {
              iVar3 = -0x6974ac88;
            }
          }
          else if (iVar4 == -0x261258ed) {
            uVar1 = (x.600 + -1) * x.600;
            bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
            iVar3 = -0x2b9597ab;
            if (9 < y.601 == bVar2 && (9 < y.601 || bVar2)) {
              iVar3 = -0x6974ac88;
            }
          }
          else if (iVar4 == -0x152ff5a5) {
            iVar3 = 0x78b87cc6;
          }
        }
        if (iVar4 != -0x4b7ea83c) break;
        __android_log_print(4,&DAT_0013f18c,&DAT_0013ffc0,local_80);
        unaff_w28 = 1;
        unaff_w20 = 1;
        iVar3 = 0x5e3728b4;
      }
    } while (iVar4 != -0x31371113);
    local_94 = local_70 + 1;
    local_9c = local_6c;
  } while( true );
}

