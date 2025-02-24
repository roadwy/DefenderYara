
rule Trojan_Win32_StealC_ASE_MTB{
	meta:
		description = "Trojan:Win32/StealC.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 b4 28 42 8f 70 c7 45 88 96 12 5b 75 c7 45 90 c0 05 ea 13 c7 45 b0 41 95 0b 62 c7 45 d0 ab fb 80 5e c7 45 98 52 8b 88 7e c7 45 84 88 91 df 61 c7 45 80 aa 0d a4 3c c7 45 bc 68 84 b9 07 c7 45 e8 c3 8c be 47 c7 45 f0 e5 ad c2 3b c7 45 9c 4e 27 3b 7f c7 45 f4 74 d4 ea 01 } //2
		$a_01_1 = {8b c7 c1 e8 05 8d 0c 3a 89 45 fc 8b 45 e8 01 45 fc 8b d7 c1 e2 04 03 55 e0 33 55 fc 33 d1 89 55 e4 8b 45 e4 29 45 f4 8b 45 dc 29 45 f8 83 6d ec 01 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}