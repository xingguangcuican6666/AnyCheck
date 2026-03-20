
/* WARNING: Type propagation algorithm not settling */

undefined4 Java_luna_safe_luna_MainActivity_checksuskernel(void)

{
  uint uVar1;
  uint uVar2;
  stat *__buf;
  bool bVar3;
  int iVar4;
  undefined4 unaff_w22;
  undefined1 auStack_80 [6];
  byte local_7a;
  byte local_79;
  stat *local_78;
  stat *local_70;
  char local_62;
  char local_61;
  
  __buf = (stat *)auStack_80;
  local_7a = (~((x.620 + -1) * x.620) | 0xfffffffeU) == 0xffffffff;
  local_79 = y.621 < 10;
  iVar4 = -0x596339ff;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while (0x1994cd7b < iVar4) {
            if (iVar4 < 0x513ee0b4) {
              if (iVar4 == 0x1994cd7c) {
                unaff_w22 = 0;
                iVar4 = -0x5d3da7e6;
              }
              else if ((iVar4 == 0x495129f7) && (iVar4 = -0x4bfc1093, local_61 == '\0')) {
                iVar4 = 0x1994cd7c;
              }
            }
            else if (iVar4 == 0x513ee0b4) {
              uVar1 = (uint)local_78->st_nlink;
              uVar2 = (x.620 + -1) * x.620;
              local_61 = ((uVar1 ^ 0xfffffe00) & uVar1) != 0x16d;
              bVar3 = ((uVar2 ^ 0xfffffffe) & uVar2) == 0;
              iVar4 = 0x495129f7;
              if ((y.621 >= 10 || !bVar3) && y.621 < 10 == bVar3) {
                iVar4 = -0x2e310a7c;
              }
            }
            else if (iVar4 == 0x6a1b2728) {
              uVar1 = (x.620 + -1) * x.620;
              bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
              iVar4 = 0x513ee0b4;
              if (y.621 < 10 == bVar3 && (9 < y.621 || !bVar3)) {
                iVar4 = -0x2e310a7c;
              }
            }
            else if (iVar4 == 0x7b28a46c) {
              __buf = (stat *)((long)(__buf + 0xffffffffffffffff) + 0x10);
              local_78 = __buf;
              local_70 = __buf;
              iVar4 = stat((char *)&DAT_00140650,__buf);
              local_62 = iVar4 == 0;
              uVar1 = (x.620 + -1) * x.620;
              bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
              iVar4 = -0x7f62ba5f;
              if ((y.621 >= 10 || !bVar3) && y.621 < 10 == bVar3) {
                iVar4 = -0x116701cc;
              }
            }
          }
          if (iVar4 < -0x4bfc1093) break;
          if (iVar4 == -0x4bfc1093) {
            __android_log_print(3,&DAT_0013e9f8,&DAT_00140660);
            unaff_w22 = 1;
            iVar4 = -0x5d3da7e6;
          }
          else if (iVar4 == -0x2e310a7c) {
            iVar4 = 0x513ee0b4;
          }
          else if (iVar4 == -0x116701cc) {
            __buf = (stat *)((long)(__buf + 0xffffffffffffffff) + 0x10);
            stat((char *)&DAT_00140650,__buf);
            iVar4 = 0x7b28a46c;
          }
        }
        if (iVar4 != -0x7f62ba5f) break;
        iVar4 = 0x6a1b2728;
        if (local_62 == '\0') {
          iVar4 = 0x1994cd7c;
        }
      }
      if (iVar4 != -0x596339ff) break;
      iVar4 = 0x7b28a46c;
      if (((local_7a ^ 1 ^ local_79 ^ 1 | (local_7a ^ 1 | local_79 ^ 1) ^ 0xff) & 1) == 0) {
        iVar4 = -0x116701cc;
      }
    }
  } while (iVar4 != -0x5d3da7e6);
  return unaff_w22;
}

