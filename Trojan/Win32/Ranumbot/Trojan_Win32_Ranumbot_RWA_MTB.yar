
rule Trojan_Win32_Ranumbot_RWA_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f6 85 ff 7e 90 01 01 55 8b 2d 90 01 04 8b ff e8 90 01 04 30 04 1e 83 ff 19 75 90 01 01 6a 00 6a 00 6a 00 6a 00 ff d5 46 3b f7 7c 90 01 01 5d 5e 81 ff 71 11 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}