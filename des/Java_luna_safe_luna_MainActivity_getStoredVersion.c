
undefined8 Java_luna_safe_luna_MainActivity_getStoredVersion(long *param_1)

{
  bool bVar1;
  uint uVar2;
  bool bVar3;
  bool bVar4;
  int iVar5;
  undefined8 local_48;
  
  uVar2 = (x.570 + -1) * x.570;
  bVar3 = ((uVar2 ^ 0xfffffffe) & uVar2) == 0;
  bVar1 = y.571 < 10;
  iVar5 = 0x4f68ab4e;
  while( true ) {
    while (0x4f68ab4d < iVar5) {
      if (iVar5 == 0x50ef66a6) {
        local_48 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_00143838);
        bVar4 = (~((x.570 + -1) * x.570) | 0xfffffffeU) == 0xffffffff;
        iVar5 = -0x14fedb8c;
        if (y.571 < 10 == bVar4 && (9 < y.571 || !bVar4)) {
          iVar5 = 0x2c46927e;
        }
      }
      else if ((iVar5 == 0x4f68ab4e) && (iVar5 = 0x50ef66a6, (!bVar3 || !bVar1) && bVar3 == bVar1))
      {
        iVar5 = 0x2c46927e;
      }
    }
    if (iVar5 == -0x14fedb8c) break;
    if (iVar5 == 0x2c46927e) {
      (**(code **)(*param_1 + 0x538))(param_1,&DAT_00143838);
      iVar5 = 0x50ef66a6;
    }
  }
  return local_48;
}

