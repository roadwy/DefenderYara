
rule Trojan_Win32_Dridex_DC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 66 01 05 ?? ?? ?? ?? 8d 04 3f 2b c8 0f b7 c3 2b c6 89 0d ?? ?? ?? ?? 8b 4c 24 18 83 c0 06 a3 ?? ?? ?? ?? 8b 44 24 14 05 24 73 02 01 a3 ?? ?? ?? ?? 89 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_DC_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 08 03 32 8b 45 08 89 30 8b 4d f4 81 c1 ?? ?? ?? ?? 8b 55 08 8b 02 2b c1 8b 4d 08 89 01 } //10
		$a_02_1 = {03 4d c4 8b 15 ?? ?? ?? ?? 2b d1 89 15 ?? ?? ?? ?? b8 73 00 00 00 85 c0 0f 85 23 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}