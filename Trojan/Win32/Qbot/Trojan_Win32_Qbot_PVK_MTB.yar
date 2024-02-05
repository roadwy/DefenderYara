
rule Trojan_Win32_Qbot_PVK_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 83 ec 48 56 a3 90 09 05 00 a1 90 00 } //01 00 
		$a_02_1 = {30 04 1e 46 3b f7 7c 90 09 05 00 e8 90 00 } //02 00 
		$a_00_2 = {8a 0c 1f 8b 7c 24 20 32 0c 37 8b 74 24 24 88 0c 1e } //02 00 
		$a_00_3 = {8a 3c 3e 03 4d e8 89 4d e8 30 fb 8b 4d dc 88 1c 39 } //02 00 
		$a_02_4 = {8a 54 0d e4 30 14 38 83 f9 14 75 90 01 01 33 c9 eb 90 00 } //02 00 
		$a_00_5 = {8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 51 8b 4d 0c 03 4d fc 88 01 } //02 00 
		$a_00_6 = {0f b6 c0 33 d8 8b 45 08 03 45 0c 88 18 8b 45 0c 48 89 45 0c } //00 00 
	condition:
		any of ($a_*)
 
}