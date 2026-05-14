
rule Trojan_Win32_Zbot_BAM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 cc 33 d2 b9 10 00 00 00 f7 f1 8b 45 cc 8a 88 ?? ?? ?? ?? 2a 8a ?? ?? ?? ?? 8b 55 cc 88 8a ?? ?? ?? ?? eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zbot_BAM_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f fd dc 57 0f 62 c5 0f d5 f2 66 0f 74 fa 0f e9 c4 31 37 66 0f dc cc 0f 74 f2 0f dd f5 83 c7 04 0f 65 fe 0f fd e8 0f 76 da } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}