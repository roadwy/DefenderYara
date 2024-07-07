
rule Trojan_Win32_Gozi_GW_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 68 cc f8 00 00 51 8d 50 90 01 01 50 89 15 90 01 04 e8 90 01 04 8b cf 33 f6 2b c8 1b f2 89 0d 90 01 04 89 35 90 01 04 c6 05 90 01 05 ff 15 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GW_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 02 88 01 8b 4d 90 01 01 83 c1 01 89 4d 90 00 } //10
		$a_02_1 = {03 c1 0f b7 55 90 01 01 2b c2 a2 90 01 04 0f b7 45 90 01 01 83 e8 90 01 01 99 8b c8 8b f2 2b 4d 90 01 01 1b 75 90 01 01 0f b6 45 90 01 01 99 03 c1 13 d6 88 45 90 01 01 8b 15 90 01 04 81 c2 90 01 04 89 15 90 01 04 a1 90 01 04 03 45 90 01 01 8b 0d 90 01 04 89 88 90 01 04 e9 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}