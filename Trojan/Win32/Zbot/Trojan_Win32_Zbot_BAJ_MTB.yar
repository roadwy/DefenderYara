
rule Trojan_Win32_Zbot_BAJ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c1 32 d8 89 44 24 ?? 8a 84 24 ?? ?? ?? ?? 8d bc 14 ?? ?? ?? ?? 88 1f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zbot_BAJ_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 c0 33 02 83 c2 04 f7 d8 83 e8 29 83 e8 02 40 29 f8 89 c7 c7 46 ?? ?? ?? ?? ?? 31 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}