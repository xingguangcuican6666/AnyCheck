
undefined8 Java_luna_safe_luna_MainActivity_KKajGz(long *param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  int iVar7;
  int iVar8;
  code *pcVar9;
  int local_64;
  
  pcVar9 = *(code **)(*param_1 + 0x560);
  uVar5 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
  uVar5 = (*pcVar9)(param_1,0x61,uVar5,0);
  iVar7 = 0;
  do {
    uVar1 = (x.544 + -1) * x.544 & 1;
    iVar2 = -0x3807a5b0;
    if (y.545 < 10 == (uVar1 == 0) && (9 < y.545 | uVar1) == 1) {
      iVar2 = 0x55d22d84;
    }
    uVar1 = (x.544 + -1) * x.544 & 1;
    iVar3 = 0x610ed377;
    if (y.545 < 10 == (uVar1 == 0) && (9 < y.545 | uVar1) == 1) {
      iVar3 = 0x55d22d84;
    }
    iVar4 = -0x38b49197;
    while( true ) {
      while (iVar8 = iVar4, 0x195fa5bb < iVar8) {
        iVar4 = iVar3;
        if (iVar8 != 0x195fa5bc) {
          if (iVar8 == 0x55d22d84) {
            iVar4 = 0x610ed377;
          }
          else {
            iVar4 = iVar8;
            if (iVar8 == 0x610ed377) {
              iVar4 = iVar2;
            }
          }
        }
      }
      if (iVar8 == -0x6f8c6980) break;
      if (iVar8 == -0x38b49197) {
        iVar4 = -0x6f8c6980;
        local_64 = iVar7;
        if (0x60 < iVar7) {
          iVar4 = 0x195fa5bc;
        }
      }
      else {
        iVar4 = iVar8;
        if (iVar8 == -0x3807a5b0) {
          return uVar5;
        }
      }
    }
    pcVar9 = *(code **)(*param_1 + 0x570);
    uVar6 = (**(code **)(*param_1 + 0x538))(param_1,(&PTR_DAT_0013ce20)[local_64]);
    (*pcVar9)(param_1,uVar5,local_64,uVar6);
    iVar7 = local_64 + 1;
  } while( true );
}

