
rule Trojan_Win32_Ranumbot_RTB_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f6 3b fd 7e 90 01 01 8b 2d 90 02 06 e8 90 01 04 30 04 1e 83 ff 19 75 90 01 01 6a 00 6a 00 6a 00 6a 00 ff d5 46 3b f7 7c 90 01 01 33 ed 81 ff 71 11 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}