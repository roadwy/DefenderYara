
rule Trojan_Win32_Danabot_GKM_MTB{
	meta:
		description = "Trojan:Win32/Danabot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 f6 89 15 90 01 04 85 c0 76 90 01 01 8b 3d 90 01 04 8b 0d 90 01 04 8a 94 31 90 01 04 8b 0d 90 01 04 88 14 31 3d 03 02 00 00 75 90 01 01 6a 00 6a 00 ff d7 a1 90 01 04 c7 05 90 01 04 74 19 00 00 46 3b f0 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}