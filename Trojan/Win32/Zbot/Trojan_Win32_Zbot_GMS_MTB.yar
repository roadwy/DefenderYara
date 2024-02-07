
rule Trojan_Win32_Zbot_GMS_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 0f b6 80 50 d0 d1 14 33 45 f4 8b 4d f4 88 81 50 d0 d1 14 eb 01 } //01 00 
		$a_01_1 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //01 00  GetProcAddress
		$a_01_2 = {4c 6f 61 64 4d 6f 64 75 6c 65 } //00 00  LoadModule
	condition:
		any of ($a_*)
 
}