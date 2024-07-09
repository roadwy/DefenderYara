
rule Trojan_Win32_Danabot_AA_MTB{
	meta:
		description = "Trojan:Win32/Danabot.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c8 03 7c 24 ?? 0f 57 c0 81 3d [0-30] c7 05 [0-30] 66 0f 13 05 [0-30] 89 4c 24 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Danabot_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Danabot.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 00 88 45 ?? 8a 45 ?? 04 9f 2c 1a 73 ?? 80 6d ?? 20 a1 ?? ?? ?? ?? 8a 00 88 45 ?? 8a 45 ?? 04 9f 2c 1a 73 ?? 80 6d ?? 20 a1 ?? ?? ?? ?? 8a 00 88 45 ?? 8a 45 ?? 04 9f 2c 1a 73 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}