
undefined8 Java_luna_safe_luna_MainActivity_wNxM8s(long *param_1)

{
  bool bVar1;
  uint uVar2;
  bool bVar3;
  bool bVar4;
  undefined8 uVar5;
  int iVar6;
  code *pcVar7;
  int local_78;
  undefined8 local_70;
  int local_64;
  
  uVar2 = (x.540 + -1) * x.540;
  bVar3 = ((uVar2 ^ 0xfffffffe) & uVar2) == 0;
  bVar1 = y.541 < 10;
  iVar6 = -0x7ef94b15;
LAB_00106e4c:
  while( true ) {
    while( true ) {
      while (iVar6 < 0x2e34d5b7) {
        if (iVar6 == -0x7ef94b15) {
          iVar6 = 0x502ec44f;
          if ((!bVar3 || !bVar1) && bVar3 == bVar1) {
            iVar6 = 0x57e67e68;
          }
        }
        else if (iVar6 == -0x7eac5260) {
          local_64 = local_78;
          iVar6 = 0x61a84de0;
          if (0x36 < local_78) {
            iVar6 = -0x4cfc7067;
          }
        }
        else if (iVar6 == -0x4cfc7067) {
          return local_70;
        }
      }
      if (iVar6 < 0x57e67e68) break;
      if (iVar6 != 0x57e67e68) goto code_r0x00106f38;
      pcVar7 = *(code **)(*param_1 + 0x560);
      uVar5 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
      (*pcVar7)(param_1,0x37,uVar5,0);
      iVar6 = 0x502ec44f;
    }
    if (iVar6 == 0x2e34d5b7) break;
    if (iVar6 == 0x502ec44f) {
      pcVar7 = *(code **)(*param_1 + 0x560);
      uVar5 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
      local_70 = (*pcVar7)(param_1,0x37,uVar5,0);
      uVar2 = (x.540 + -1) * x.540;
      bVar4 = ((uVar2 ^ 0xfffffffe) & uVar2) == 0;
      iVar6 = 0x2e34d5b7;
      if (y.541 < 10 == bVar4 && (9 < y.541 || !bVar4)) {
        iVar6 = 0x57e67e68;
      }
    }
  }
  local_78 = 0;
  goto LAB_00106fa4;
code_r0x00106f38:
  if (iVar6 == 0x61a84de0) {
    pcVar7 = *(code **)(*param_1 + 0x570);
    uVar5 = (**(code **)(*param_1 + 0x538))(param_1,(&PTR_DAT_0013e840)[local_64]);
    (*pcVar7)(param_1,local_70,local_64,uVar5);
    local_78 = local_64 + 1;
LAB_00106fa4:
    iVar6 = -0x7eac5260;
  }
  goto LAB_00106e4c;
}

