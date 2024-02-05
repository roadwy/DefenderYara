
rule Trojan_Win32_Qbot_VSD_MTB{
	meta:
		description = "Trojan:Win32/Qbot.VSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 14 89 48 04 8b 8c 24 90 01 04 5f 5e 89 28 5d 33 cc e8 90 01 04 81 c4 2c 08 00 00 90 00 } //02 00 
		$a_02_1 = {89 d8 83 e0 1f 8a 80 90 01 04 30 04 1e e8 90 01 04 30 04 1e 43 39 fb 75 90 00 } //02 00 
		$a_02_2 = {8b 45 10 03 85 90 01 04 8a 08 32 8c 15 90 01 04 8b 55 10 03 95 90 01 04 88 0a 90 00 } //02 00 
		$a_02_3 = {8b 44 24 48 8b 54 24 90 01 01 8a 1c 0a 32 5c 24 90 01 01 8b 4c 24 90 01 01 88 1c 01 8b 44 24 48 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}