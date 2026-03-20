
undefined8
Java_luna_safe_luna_MainActivity_encryptData(long *param_1,undefined8 param_2,undefined8 param_3)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  char *pcVar4;
  size_t sVar5;
  void *pvVar6;
  void *pvVar7;
  uint uVar8;
  undefined8 local_68;
  
  bVar2 = (~((x.562 + 0xaf8491d) * x.562) | 0xfffffffeU) == 0xffffffff;
  bVar1 = y.563 < 10;
  uVar8 = 0x23a2e1d0;
  do {
    while( true ) {
      while (0x23a2e1cf < uVar8) {
        if (uVar8 == 0x55217792) {
          pcVar4 = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_3,0);
          sVar5 = strlen(pcVar4);
          pvVar6 = malloc(sVar5 + 1);
          xorEncryptDecrypt(pcVar4,(long)pvVar6,(char *)&DAT_0013f668);
          pvVar7 = malloc((sVar5 + 2) / 3 << 2 | 1);
          base64_encode((long)pvVar6,sVar5,(long)pvVar7);
          local_68 = (**(code **)(*param_1 + 0x538))(param_1,pvVar7);
          free(pvVar6);
          free(pvVar7);
          (**(code **)(*param_1 + 0x550))(param_1,param_3,pcVar4);
          uVar8 = (x.562 + -1) * x.562;
          bVar3 = ((uVar8 ^ 0xfffffffe) & uVar8) == 0;
          uVar8 = 0xdd63d55;
          if ((y.563 >= 10 || !bVar3) && y.563 < 10 == bVar3) {
            uVar8 = 0x7ee948;
          }
        }
        else if ((uVar8 == 0x23a2e1d0) && (uVar8 = 0x55217792, (!bVar2 || !bVar1) && bVar2 == bVar1)
                ) {
          uVar8 = 0x7ee948;
        }
      }
      if (uVar8 != 0x7ee948) break;
      pcVar4 = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_3,0);
      sVar5 = strlen(pcVar4);
      pvVar6 = malloc(sVar5 + 1);
      xorEncryptDecrypt(pcVar4,(long)pvVar6,(char *)&DAT_0013f668);
      pvVar7 = malloc((sVar5 + 2) / 3 << 2 | 1);
      base64_encode((long)pvVar6,sVar5,(long)pvVar7);
      (**(code **)(*param_1 + 0x538))(param_1,pvVar7);
      free(pvVar6);
      free(pvVar7);
      (**(code **)(*param_1 + 0x550))(param_1,param_3,pcVar4);
      uVar8 = 0x55217792;
    }
  } while (uVar8 != 0xdd63d55);
  return local_68;
}

