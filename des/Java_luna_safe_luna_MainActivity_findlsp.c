
undefined4 Java_luna_safe_luna_MainActivity_findlsp(void)

{
  uint uVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  undefined4 unaff_w23;
  int unaff_w26;
  undefined1 auStack_80 [6];
  byte local_7a;
  byte local_79;
  char *local_78;
  char *local_70;
  char local_61;
  
  pcVar5 = auStack_80;
  uVar1 = (x.624 + -1) * x.624;
  local_7a = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
  local_79 = y.625 < 10;
  iVar3 = -0x63f92fc3;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while (0x1fc169a4 < iVar3) {
            if (iVar3 < 0x65f2dc3e) {
              if (iVar3 == 0x1fc169a5) {
                unaff_w26 = 0;
                iVar3 = 0x61e5833c;
              }
              else if (iVar3 == 0x427994e3) {
                __android_log_print(3,&DAT_0013e9f8,&DAT_001407d0,local_70);
                unaff_w26 = 1;
                iVar3 = 0x61e5833c;
              }
              else if (iVar3 == 0x61e5833c) {
                iVar3 = 0x75c476e1;
                if (unaff_w26 != 0) {
                  iVar3 = -0x625d38bb;
                }
                unaff_w23 = 1;
              }
            }
            else if (iVar3 == 0x65f2dc3e) {
              __android_log_print(3,&DAT_0013e9f8,&DAT_001407f0);
              iVar3 = -0x665998fa;
            }
            else if (iVar3 == 0x74f32cbd) {
              iVar4 = atoi(local_70);
              iVar3 = 0x427994e3;
              if (iVar4 < 1) {
                iVar3 = 0x1fc169a5;
              }
            }
            else if ((iVar3 == 0x75c476e1) &&
                    (uVar1 = (x.624 + -1) * x.624, bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0,
                    iVar3 = -0x665998fa, 9 < y.625 == bVar2 && (9 < y.625 || bVar2))) {
              iVar3 = 0x65f2dc3e;
            }
          }
          if (-0x625d38bc < iVar3) break;
          if (iVar3 == -0x665998fa) {
            __android_log_print(3,&DAT_0013e9f8,&DAT_001407f0);
            uVar1 = (x.624 + -1) * x.624 & 1;
            iVar3 = -0x51eb0f9b;
            if (9 < y.625 == uVar1 && (9 < y.625 | uVar1) == 1) {
              iVar3 = 0x65f2dc3e;
            }
          }
          else if (iVar3 == -0x63f92fc3) {
            iVar3 = -0x49e77afe;
            if (((local_7a ^ 1 ^ local_79 ^ 1 | (local_7a ^ 1 | local_79 ^ 1) ^ 0xff) & 1) == 0) {
              iVar3 = -0x25b336cc;
            }
          }
          else if (iVar3 == -0x629bd8d2) {
            iVar3 = 0x74f32cbd;
            if (local_61 == '\0') {
              iVar3 = 0x75c476e1;
            }
          }
        }
        if (iVar3 < -0x49e77afe) break;
        if (iVar3 == -0x49e77afe) {
          pcVar5 = pcVar5 + -0x60;
          local_78 = pcVar5;
          local_70 = pcVar5;
          iVar3 = __system_property_get(&DAT_001407b0,pcVar5);
          local_61 = 0 < iVar3;
          uVar1 = (x.624 + -1) * x.624;
          bVar2 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
          iVar3 = -0x629bd8d2;
          if (9 < y.625 == bVar2 && (9 < y.625 || bVar2)) {
            iVar3 = -0x25b336cc;
          }
        }
        else if (iVar3 == -0x25b336cc) {
          pcVar5 = pcVar5 + -0x60;
          __system_property_get(&DAT_001407b0);
          iVar3 = -0x49e77afe;
        }
      }
      if (iVar3 != -0x51eb0f9b) break;
      unaff_w23 = 0;
      iVar3 = -0x625d38bb;
    }
  } while (iVar3 != -0x625d38bb);
  return unaff_w23;
}

