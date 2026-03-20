
undefined1 Java_luna_safe_luna_MainActivity_checkxiaomi(void)

{
  uint uVar1;
  int iVar2;
  bool bVar3;
  int iVar4;
  undefined1 unaff_w25;
  undefined1 auStack_cc [92];
  undefined1 *local_70;
  int local_68;
  undefined1 local_64;
  
  local_70 = auStack_cc;
  local_68 = __system_property_get(local_70,&DAT_001404f0,auStack_cc);
  iVar2 = -0x4883d3db;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while (iVar4 = iVar2, iVar2 = iVar4, iVar4 < -0x1be3622a) {
            if (iVar4 < -0x3e389ac4) {
              if (iVar4 == -0x5af54d0c) {
                unaff_w25 = 0;
                iVar2 = -0x1be3622a;
              }
              else if (iVar4 == -0x4883d3db) {
                iVar2 = -0x4796cca5;
                if (local_68 < 1) {
                  iVar2 = 0x3f331b8b;
                }
              }
              else if ((iVar4 == -0x4796cca5) &&
                      (uVar1 = (x.608 + -1) * x.608 & 1, iVar2 = 0x64673253,
                      9 < y.609 == uVar1 && (9 < y.609 | uVar1) == 1)) {
                iVar2 = 0x46abb24a;
              }
            }
            else {
              iVar2 = -0x27b1c3e3;
              if (iVar4 != -0x3e389ac4) {
                if (iVar4 == -0x2c471623) {
                  unaff_w25 = 1;
                  iVar2 = -0x1be3622a;
                }
                else {
                  iVar2 = iVar4;
                  if ((iVar4 == -0x27b1c3e3) &&
                     (uVar1 = (x.608 + -1) * x.608 & 1, iVar2 = -0x5af54d0c,
                     9 < y.609 == uVar1 && (9 < y.609 | uVar1) == 1)) {
                    iVar2 = -0x3e389ac4;
                  }
                }
              }
            }
          }
          if (iVar4 < 0x3f331b8b) break;
          if (iVar4 == 0x3f331b8b) {
            uVar1 = (x.608 + -1) * x.608 & 1;
            iVar2 = -0x27b1c3e3;
            if (y.609 < 10 == (uVar1 == 0) && (9 < y.609 | uVar1) == 1) {
              iVar2 = -0x3e389ac4;
            }
          }
          else if (iVar4 == 0x46abb24a) {
            __android_log_print(3,&DAT_0013e9f8,&DAT_00140510);
            iVar2 = 0x64673253;
          }
          else if (iVar4 == 0x64673253) {
            __android_log_print(3,&DAT_0013e9f8,&DAT_00140510);
            uVar1 = (x.608 + -1) * x.608 & 1;
            iVar2 = -0x2c471623;
            if (y.609 < 10 == (uVar1 == 0) && (9 < y.609 | uVar1) == 1) {
              iVar2 = 0x46abb24a;
            }
          }
        }
        if (-0xdc41596 < iVar4) break;
        if (iVar4 == -0x1be3622a) {
          uVar1 = (x.608 + -1) * x.608;
          bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
          iVar2 = 0x3db759d0;
          local_64 = unaff_w25;
          if (y.609 < 10 == bVar3 && (9 < y.609 || !bVar3)) {
            iVar2 = -0x104dd97d;
          }
        }
        else if (iVar4 == -0x104dd97d) {
          iVar2 = 0x3db759d0;
        }
      }
      if (iVar4 != 0x3db759d0) break;
      bVar3 = ((x.608 + -1) * x.608 & 1U) == 0;
      iVar2 = -0xdc41595;
      if ((y.609 >= 10 || !bVar3) && y.609 < 10 == bVar3) {
        iVar2 = -0x104dd97d;
      }
    }
  } while (iVar4 != -0xdc41595);
  return local_64;
}

