
undefined8 Java_luna_safe_luna_MainActivity_K0ajGz(long *param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  bool bVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  int iVar9;
  int iVar10;
  code *pcVar11;
  int local_64;
  
  pcVar11 = *(code **)(*param_1 + 0x560);
  uVar7 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
  uVar7 = (*pcVar11)(param_1,0x8b,uVar7,0);
  iVar9 = 0;
  do {
    uVar3 = (x.542 + -1) * x.542;
    uVar4 = (x.542 + -1) * x.542;
    bVar6 = ((uVar3 ^ 0xfffffffe) & uVar3) == 0;
    iVar1 = -0x4bbe1a2b;
    if (y.543 < 10 == bVar6 && (9 < y.543 || !bVar6)) {
      iVar1 = 0x71118f4b;
    }
    bVar6 = ((uVar4 ^ 0xfffffffe) & uVar4) == 0;
    iVar2 = 0x6c20fe0e;
    if (y.543 < 10 == bVar6 && (9 < y.543 || !bVar6)) {
      iVar2 = 0x71118f4b;
    }
    iVar5 = 0xcab6e28;
    do {
      while( true ) {
        while (iVar10 = iVar5, 0x2534a531 < iVar10) {
          iVar5 = iVar2;
          if (((iVar10 != 0x2534a532) && (iVar5 = iVar1, iVar10 != 0x6c20fe0e)) &&
             (iVar5 = iVar10, iVar10 == 0x71118f4b)) {
            iVar5 = 0x6c20fe0e;
          }
        }
        if (iVar10 == -0x4bbe1a2b) {
          return uVar7;
        }
        if (iVar10 != 0xcab6e28) break;
        iVar5 = 0x1ce89de9;
        local_64 = iVar9;
        if (0x8a < iVar9) {
          iVar5 = 0x2534a532;
        }
      }
      iVar5 = iVar10;
    } while (iVar10 != 0x1ce89de9);
    pcVar11 = *(code **)(*param_1 + 0x570);
    uVar8 = (**(code **)(*param_1 + 0x538))(param_1,(&PTR_DAT_0013c9c8)[local_64]);
    (*pcVar11)(param_1,uVar7,local_64,uVar8);
    iVar9 = local_64 + 1;
  } while( true );
}

