
void Java_luna_safe_luna_MainActivity_updateStoredVersion
               (long *param_1,undefined8 param_2,undefined8 param_3)

{
  bool bVar1;
  uint uVar2;
  bool bVar3;
  bool bVar4;
  int iVar5;
  char *local_70;
  char local_61;
  
  bVar3 = (~((x.572 + -1) * x.572) | 0xfffffffeU) == 0xffffffff;
  bVar1 = y.573 < 10;
  iVar5 = -0x74f7ce91;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          while (iVar5 < 0x647d847) {
            if (iVar5 < -0x56d01cfd) {
              if (iVar5 == -0x74f7ce91) {
                iVar5 = 0x3b786d32;
                if (!(bool)(bVar3 != bVar1 | ((~bVar3 | !bVar1) ^ 1U) & 1)) {
                  iVar5 = -0x44f3af5;
                }
              }
              else if ((iVar5 == -0x5d6bb216) &&
                      (uVar2 = (x.572 + -1) * x.572 & 1, iVar5 = -0x56d01cfd,
                      9 < y.573 == uVar2 && (9 < y.573 | uVar2) == 1)) {
                iVar5 = 0x716af378;
              }
            }
            else if (iVar5 == -0x56d01cfd) {
              strncpy(&DAT_00143838,local_70,0xff);
              DAT_00143937 = 0;
              (**(code **)(*param_1 + 0x550))(param_1,param_3,local_70);
              uVar2 = (x.572 + -1) * x.572 & 1;
              iVar5 = 0x7901bd2a;
              if (9 < y.573 == uVar2 && (9 < y.573 | uVar2) == 1) {
                iVar5 = 0x716af378;
              }
            }
            else if (iVar5 == -0x44f3af5) {
              (**(code **)(*param_1 + 0x548))(param_1,param_3,0);
              iVar5 = 0x3b786d32;
            }
          }
          if (iVar5 < 0x716af378) break;
          if (iVar5 == 0x716af378) {
            strncpy(&DAT_00143838,local_70,0xff);
            DAT_00143937 = 0;
            (**(code **)(*param_1 + 0x550))(param_1,param_3,local_70);
            iVar5 = -0x56d01cfd;
          }
          else if (iVar5 == 0x7901bd2a) {
            iVar5 = 0x647d847;
          }
        }
        if (iVar5 != 0x3b786d32) break;
        local_70 = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_3,0);
        local_61 = local_70 != (char *)0x0;
        uVar2 = (x.572 + -1) * x.572;
        bVar4 = ((uVar2 ^ 0xfffffffe) & uVar2) == 0;
        iVar5 = 0x56f62260;
        if (y.573 < 10 == bVar4 && (9 < y.573 || !bVar4)) {
          iVar5 = -0x44f3af5;
        }
      }
      if (iVar5 != 0x56f62260) break;
      iVar5 = -0x5d6bb216;
      if (local_61 == '\0') {
        iVar5 = 0x647d847;
      }
    }
  } while (iVar5 != 0x647d847);
  return;
}

