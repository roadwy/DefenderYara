
rule Trojan_Win32_Dridex_EG_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EG!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7c 24 14 f7 d7 8b 5c 24 20 f7 d3 89 5c 24 3c 89 7c 24 38 88 14 08 eb 0b } //10
		$a_01_1 = {8a 44 24 0b 24 3b 8b 4d 10 8b 54 24 2c 88 44 24 37 39 ca } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Dridex_EG_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.EG!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 57 fe 8b da 33 d2 2b d8 1b ea 0f b7 c6 99 2b d8 1b ea 03 cb 8b 5c 24 1c 13 dd 8b 6c 24 10 } //10
		$a_01_1 = {0f b7 d6 be 0e 00 00 00 2b f2 2b f0 8b 45 00 05 0c 46 05 01 89 45 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}