
rule Trojan_Win32_Zbot_RA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d9 2b df 2b d8 8b 44 24 14 8b 00 81 eb 87 28 00 00 8b fb 8b 5c 24 1c 03 d9 8d 9c 2b ?? ?? ?? ?? 89 1d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zbot_RA_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 7d fc 33 fe 03 c6 2b c6 56 59 46 87 c3 89 45 f4 } //1
		$a_03_1 = {47 6a 00 6a 00 6a 00 6a 00 6a 79 6a 4b 6a 76 6a 18 68 00 00 80 00 6a 00 c7 05 ?? ?? ?? ?? 4c 49 53 54 c7 05 ?? ?? ?? ?? 42 4f 58 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}