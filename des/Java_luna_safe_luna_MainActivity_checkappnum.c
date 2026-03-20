
undefined4 Java_luna_safe_luna_MainActivity_checkappnum(void)

{
  uint uVar1;
  bool bVar2;
  int iVar3;
  undefined1 *puVar4;
  undefined4 unaff_w22;
  undefined1 auStack_80 [14];
  byte bStack_72;
  byte bStack_71;
  undefined1 *puStack_70;
  char cStack_61;
  
  puVar4 = auStack_80;
  uVar1 = (x.618 + -1) * x.618;
  bStack_72 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
  bStack_71 = y.619 < 10;
  iVar3 = 0x595e5bf8;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while (iVar3 < 0x2ee635ec) {
            if (iVar3 < -0x3c4eab51) {
              if (iVar3 == -0x7048e38b) {
                iVar3 = -0x3c4eab51;
                if (cStack_61 == '\0') {
                  iVar3 = 0xd782781;
                }
              }
              else if (iVar3 == -0x671708b1) {
                puVar4 = puVar4 + -0x60;
                __system_property_get(&DAT_001405f0);
                iVar3 = 0x5bc35839;
              }
            }
            else if (iVar3 == -0x3c4eab51) {
              uVar1 = (x.618 + -1) * x.618 & 1;
              iVar3 = -0x27b0abd5;
              if (9 < y.619 == uVar1 && (9 < y.619 | uVar1) == 1) {
                iVar3 = 0x52de1877;
              }
            }
            else if (iVar3 == -0x27b0abd5) {
              __android_log_print(3,&DAT_0013e9f8,&DAT_00140620);
              uVar1 = (x.618 + -1) * x.618;
              bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
              iVar3 = 0x2ee635ec;
              if (y.619 < 10 == bVar2 && (9 < y.619 || !bVar2)) {
                iVar3 = 0x52de1877;
              }
            }
            else if (iVar3 == 0xd782781) {
              unaff_w22 = 0;
              iVar3 = 0x5667969f;
            }
          }
          if (0x5667969e < iVar3) break;
          if (iVar3 == 0x2ee635ec) {
            unaff_w22 = 1;
            iVar3 = 0x5667969f;
          }
          else if (iVar3 == 0x52de1877) {
            __android_log_print(3,&DAT_0013e9f8,&DAT_00140620);
            iVar3 = -0x27b0abd5;
          }
        }
        if (iVar3 != 0x595e5bf8) break;
        iVar3 = 0x5bc35839;
        if (((bStack_72 ^ bStack_71 | (~bStack_72 | bStack_71 ^ 0xff) ^ 0xff) & 1) == 0) {
          iVar3 = -0x671708b1;
        }
      }
      if (iVar3 != 0x5bc35839) break;
      puVar4 = puVar4 + -0x60;
      puStack_70 = puVar4;
      iVar3 = __system_property_get(puVar4,&DAT_001405f0);
      cStack_61 = 0 < iVar3;
      bVar2 = ((x.618 + -1) * x.618 & 1U) == 0;
      iVar3 = -0x7048e38b;
      if ((y.619 >= 10 || !bVar2) && y.619 < 10 == bVar2) {
        iVar3 = -0x671708b1;
      }
    }
  } while (iVar3 != 0x5667969f);
  return unaff_w22;
}

