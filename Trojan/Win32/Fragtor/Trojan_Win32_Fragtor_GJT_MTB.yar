
rule Trojan_Win32_Fragtor_GJT_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 ce c1 e9 08 33 d1 66 8b 54 93 04 c1 e6 08 66 33 d6 8b f2 eb 90 01 01 8b 55 f0 0f b6 12 8b 4d ec 81 e1 90 01 04 33 d1 8b 54 93 04 8b 4d ec c1 e9 08 33 d1 89 55 ec ff 45 f0 48 90 00 } //10
		$a_01_1 = {63 72 76 73 78 2e 7a 61 70 74 6f 2e 6f 72 67 } //1 crvsx.zapto.org
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}