
rule Trojan_Win32_Zbot_SIBC6_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBC6!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b ec 51 c7 45 90 01 05 eb 90 01 01 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 8b 4d 90 01 01 3b 4d 90 01 01 7f 90 01 01 8b 45 90 01 01 99 f7 3d 90 01 04 8b 45 90 01 01 03 45 90 01 01 8a 08 32 8a 90 01 04 8b 55 90 01 01 03 55 90 01 01 88 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}