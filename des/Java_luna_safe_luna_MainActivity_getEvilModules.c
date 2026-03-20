
undefined8 Java_luna_safe_luna_MainActivity_getEvilModules(long *param_1)

{
  uint uVar1;
  int iVar2;
  bool bVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  int iVar6;
  int iVar7;
  code *pcVar8;
  int local_68;
  int local_64;
  
  pcVar8 = *(code **)(*param_1 + 0x560);
  uVar4 = (**(code **)(*param_1 + 0x30))(param_1,&DAT_0013f170);
  uVar4 = (*pcVar8)(param_1,0xc,uVar4,0);
  iVar2 = 0;
  do {
    iVar7 = iVar2;
    iVar2 = -0x6751007d;
    while( true ) {
      while( true ) {
        while (iVar6 = iVar2, iVar2 = iVar6, iVar6 < -0x301fe554) {
          if (iVar6 < -0x646b08b9) {
            if (iVar6 == -0x7cf46479) {
              pcVar8 = *(code **)(*param_1 + 0x570);
              uVar5 = (**(code **)(*param_1 + 0x538))(param_1,(&PTR_DAT_0013d128)[local_64]);
              (*pcVar8)(param_1,uVar4,local_64,uVar5);
              local_68 = local_64 + 1;
              uVar1 = (x.546 + -1) * x.546 & 1;
              iVar2 = -0x301fe554;
              if (9 < y.547 == uVar1 && (9 < y.547 | uVar1) == 1) {
                iVar2 = -0x312f5957;
              }
            }
            else if ((iVar6 == -0x6751007d) && (iVar2 = 0x5512d83f, local_64 = iVar7, 0xb < iVar7))
            {
              iVar2 = -0x646b08b9;
            }
          }
          else if (iVar6 == -0x646b08b9) {
            uVar1 = (x.546 + -1) * x.546 & 1;
            iVar2 = 0x4b972d1a;
            if (9 < y.547 == uVar1 && (9 < y.547 | uVar1) == 1) {
              iVar2 = 0x2966dd6c;
            }
          }
          else if (iVar6 == -0x312f5957) {
            pcVar8 = *(code **)(*param_1 + 0x570);
            uVar5 = (**(code **)(*param_1 + 0x538))(param_1,(&PTR_DAT_0013d128)[local_64]);
            (*pcVar8)(param_1,uVar4,local_64,uVar5);
            iVar2 = -0x7cf46479;
          }
        }
        if (iVar6 < 0x4b972d1a) break;
        if (iVar6 == 0x4b972d1a) {
          uVar1 = (x.546 + -1) * x.546;
          bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
          iVar2 = 0x757286;
          if ((y.547 >= 10 || !bVar3) && y.547 < 10 == bVar3) {
            iVar2 = 0x2966dd6c;
          }
        }
        else if (iVar6 == 0x5512d83f) {
          uVar1 = (x.546 + -1) * x.546;
          bVar3 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
          iVar2 = -0x7cf46479;
          if ((y.547 >= 10 || !bVar3) && y.547 < 10 == bVar3) {
            iVar2 = -0x312f5957;
          }
        }
      }
      iVar2 = local_68;
      if (iVar6 == -0x301fe554) break;
      iVar2 = 0x4b972d1a;
      if ((iVar6 != 0x2966dd6c) && (iVar2 = iVar6, iVar6 == 0x757286)) {
        return uVar4;
      }
    }
  } while( true );
}

