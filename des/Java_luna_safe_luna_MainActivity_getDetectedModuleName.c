
undefined8 Java_luna_safe_luna_MainActivity_getDetectedModuleName(long *param_1)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  undefined8 local_48;
  
  bVar2 = (~((x.592 + 0x787d4a0b) * x.592) | 0xfffffffeU) != 0xffffffff;
  bVar1 = 9 < y.593;
  iVar4 = 0x17c3d949;
  do {
    while( true ) {
      while (iVar4 < 0x5462b843) {
        if (iVar4 == -0x787625fc) {
          (**(code **)(*param_1 + 0x538))(param_1,&DAT_00143939);
          iVar4 = 0x5462b843;
        }
        else if ((iVar4 == 0x17c3d949) && (iVar4 = 0x5462b843, bVar2 == bVar1 && (bVar2 || bVar1)))
        {
          iVar4 = -0x787625fc;
        }
      }
      if (iVar4 != 0x5462b843) break;
      local_48 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_00143939);
      bVar3 = (~((x.592 + -1) * x.592) | 0xfffffffeU) == 0xffffffff;
      iVar4 = 0x55bdc573;
      if (y.593 < 10 == bVar3 && (9 < y.593 || !bVar3)) {
        iVar4 = -0x787625fc;
      }
    }
  } while (iVar4 != 0x55bdc573);
  return local_48;
}

