
rule Trojan_Win32_Qbot_PAL_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d0 8b 45 90 01 01 33 10 89 55 90 01 01 8b 45 90 01 01 8b 55 90 01 01 89 02 33 c0 89 45 a4 8b 45 90 01 01 83 c0 04 03 45 90 01 01 89 45 a8 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_PAL_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.PAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 04 8b 4d 90 01 01 8a 14 02 32 14 19 8b 45 90 01 01 88 14 03 33 d2 8b 45 90 01 01 c7 85 90 02 08 8b 48 90 01 01 8b 85 d4 00 00 00 05 12 b5 ff ff 03 c1 f7 75 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}