
undefined4 Java_luna_safe_luna_MainActivity_fhma(void)

{
  __off_t _Var1;
  undefined *puVar2;
  int iVar3;
  undefined4 unaff_w24;
  undefined4 local_f4;
  stat sStack_f0;
  
  sStack_f0.__unused[1] = (long)&sStack_f0;
  sStack_f0.__unused[2]._4_4_ = stat(&DAT_00140690,&sStack_f0);
  iVar3 = 0xb22135d;
LAB_00120d04:
  do {
    while (_Var1 = sStack_f0.st_size, 0x1be454d4 < iVar3) {
      if (iVar3 < 0x20a8a3a2) {
        if (iVar3 == 0x1be454d5) {
          local_f4 = unaff_w24;
          iVar3 = 0x20a8a3a2;
        }
        else if (iVar3 == 0x1e9e69f4) {
          unaff_w24 = 0;
          puVar2 = &DAT_00140770;
LAB_00120dac:
          __android_log_print(4,&DAT_0013f18c,puVar2);
          iVar3 = 0x1be454d5;
        }
      }
      else {
        if (iVar3 == 0x20a8a3a2) {
          return local_f4;
        }
        if ((iVar3 == 0x35b83e19) &&
           (__android_log_print(4,&DAT_0013f18c,&DAT_00140710,&DAT_00140690,sStack_f0.st_size),
           iVar3 = 0x11fb7ae2, 0x7ff < _Var1)) {
          iVar3 = 0x1e9e69f4;
        }
      }
    }
    if (iVar3 == -0x2b3dcfe5) {
      __android_log_print(4,&DAT_0013f18c,&DAT_001406c0,&DAT_00140690);
      local_f4 = 0;
      iVar3 = 0x20a8a3a2;
      goto LAB_00120d04;
    }
    if (iVar3 == 0xb22135d) {
      iVar3 = 0x35b83e19;
      if (sStack_f0.__unused[2]._4_4_ != 0) {
        iVar3 = -0x2b3dcfe5;
      }
    }
    else if (iVar3 == 0x11fb7ae2) {
      unaff_w24 = 1;
      puVar2 = &DAT_00140740;
      goto LAB_00120dac;
    }
  } while( true );
}

