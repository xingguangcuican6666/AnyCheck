
undefined4 Java_luna_safe_luna_MainActivity_checkdns(void)

{
  uint uVar1;
  int iVar2;
  addrinfo **ppaVar3;
  bool bVar4;
  int iVar5;
  char *pcVar6;
  addrinfo **ppaVar7;
  undefined4 unaff_w22;
  undefined4 unaff_w25;
  addrinfo *__req;
  undefined1 auStack_b0 [14];
  byte bStack_a2;
  byte bStack_a1;
  addrinfo **ppaStack_a0;
  addrinfo **ppaStack_98;
  addrinfo *paStack_90;
  addrinfo **ppaStack_88;
  addrinfo **ppaStack_80;
  int iStack_78;
  char cStack_71;
  addrinfo *paStack_68;
  
  uVar1 = (x.584 + -1) * x.584;
  bStack_a2 = ((uVar1 ^ 0xfffffffe) & uVar1) == 0;
  bStack_a1 = y.585 < 10;
  ppaVar3 = (addrinfo **)auStack_b0;
  iVar2 = -0x59f29abb;
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          iVar5 = iVar2;
          ppaVar7 = ppaStack_98;
          iVar2 = iVar5;
          if (-0xfc28006 < iVar5) break;
          if (iVar5 < -0x3ba873a4) {
            if (iVar5 == -0x746353d2) {
              __android_log_print(4,&DAT_0013f18c,&DAT_0013f8b0);
              ppaVar3[-5] = (addrinfo *)0x0;
              ppaVar3[-6] = (addrinfo *)0x0;
              ppaVar3[-3] = (addrinfo *)0x0;
              ppaVar3[-4] = (addrinfo *)0x0;
              ppaVar3[-1] = (addrinfo *)0x0;
              ppaVar3[-2] = (addrinfo *)0x0;
              *(undefined8 *)((long)ppaVar3 + -0x2c) = 0x100000002;
              getaddrinfo((char *)&DAT_0013f8c8,(char *)0x0,(addrinfo *)(ppaVar3 + -6),ppaVar3 + -8)
              ;
              ppaVar3 = ppaVar3 + -8;
              iVar2 = 0x49797d91;
            }
            else if (iVar5 == -0x6a325bbf) {
              inet_ntop(paStack_68->ai_family,paStack_68->ai_canonname + 4,(char *)ppaStack_98,100);
              __android_log_print(4,&DAT_0013f18c,&DAT_0013f910,ppaVar7);
              iVar5 = strcmp((char *)ppaVar7,(char *)&DAT_0013f8d8);
              iVar2 = -0x36d9610d;
              if (iVar5 != 0) {
                iVar2 = 0x5224536a;
              }
            }
            else if ((iVar5 == -0x59f29abb) &&
                    (iVar2 = 0x49797d91, ((bStack_a2 & bStack_a1 | bStack_a2 ^ bStack_a1) & 1) == 0)
                    ) {
              iVar2 = -0x746353d2;
            }
          }
          else if (iVar5 == -0x3ba873a4) {
            freeaddrinfo(*ppaStack_a0);
            iVar2 = 0x439cd428;
            unaff_w22 = unaff_w25;
          }
          else if (iVar5 == -0x36d9610d) {
            unaff_w25 = 1;
            iVar2 = -0x3ba873a4;
          }
          else if (iVar5 == -0x29984461) {
            unaff_w25 = 0;
            paStack_68 = *ppaStack_a0;
            iVar2 = -0x3ba873a4;
            if (paStack_68 != (addrinfo *)0x0) {
              iVar2 = -0x6a325bbf;
            }
          }
        }
        if (iVar5 < 0x49797d91) break;
        if (iVar5 == 0x49797d91) {
          __req = (addrinfo *)(ppaVar3 + -6);
          ppaStack_a0 = ppaVar3 + -8;
          ppaVar7 = ppaVar3 + -0x16;
          ppaStack_98 = ppaVar7;
          __android_log_print(4,&DAT_0013f18c,&DAT_0013f8b0);
          ppaStack_88 = ppaStack_a0;
          ppaStack_80 = ppaStack_98;
          ppaVar3[-5] = (addrinfo *)0x0;
          __req->ai_flags = 0;
          __req->ai_family = 0;
          ppaVar3[-3] = (addrinfo *)0x0;
          ppaVar3[-4] = (addrinfo *)0x0;
          ppaVar3[-1] = (addrinfo *)0x0;
          ppaVar3[-2] = (addrinfo *)0x0;
          *(undefined8 *)((long)ppaVar3 + -0x2c) = 0x100000002;
          paStack_90 = __req;
          iStack_78 = getaddrinfo((char *)&DAT_0013f8c8,(char *)0x0,__req,ppaStack_a0);
          cStack_71 = iStack_78 != 0;
          uVar1 = (x.584 + -1) * x.584;
          bVar4 = ((uVar1 ^ 0xfffffffe) & uVar1) != 0;
          ppaVar3 = ppaVar7;
          iVar2 = 0x77185c64;
          if (9 < y.585 == bVar4 && (9 < y.585 || bVar4)) {
            iVar2 = -0x746353d2;
          }
        }
        else if (iVar5 == 0x5224536a) {
          *ppaStack_a0 = (*ppaStack_a0)->ai_next;
          iVar2 = -0x29984461;
        }
        else if (iVar5 == 0x77185c64) {
          iVar2 = -0xfc28005;
          if (cStack_71 == '\0') {
            iVar2 = 0x364697f0;
          }
        }
      }
      if (iVar5 != -0xfc28005) break;
      pcVar6 = gai_strerror(iStack_78);
      __android_log_print(4,&DAT_0013f18c,&DAT_0013f8f0,pcVar6);
      unaff_w22 = 0;
      iVar2 = 0x439cd428;
    }
    iVar2 = -0x29984461;
  } while ((iVar5 == 0x364697f0) || (iVar2 = iVar5, iVar5 != 0x439cd428));
  return unaff_w22;
}

