
rule Trojan_Win32_Lokibot_BA_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 8b 1d c0 00 00 00 83 fb 00 74 90 01 01 eb 90 00 } //01 00 
		$a_03_1 = {50 89 e0 83 c4 06 ff 28 e8 90 01 02 ff ff c3 90 00 } //01 00 
		$a_03_2 = {66 81 fb cd 03 0f 84 90 01 01 00 00 66 8b 18 66 81 fb 0f 0b 0f 84 90 01 01 00 00 ff d0 eb 90 00 } //01 00 
		$a_03_3 = {80 fb cc 0f 84 90 01 01 00 00 66 8b 18 eb 90 00 } //01 00 
		$a_01_4 = {81 ec 00 01 00 00 81 ed 00 01 00 00 61 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}