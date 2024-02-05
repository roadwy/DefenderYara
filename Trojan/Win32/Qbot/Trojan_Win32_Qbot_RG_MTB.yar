
rule Trojan_Win32_Qbot_RG_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 90 01 04 2b d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 25 ff 00 00 00 0f b6 90 01 05 30 14 37 83 6c 24 90 01 01 01 8b 74 24 90 01 01 85 f6 90 00 } //02 00 
		$a_02_1 = {81 e1 ff 00 00 00 8a 91 90 01 04 0f b6 c2 03 05 90 01 04 89 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}