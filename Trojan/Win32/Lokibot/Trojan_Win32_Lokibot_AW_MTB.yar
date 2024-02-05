
rule Trojan_Win32_Lokibot_AW_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f ef c1 51 0f 7e c1 88 c8 59 29 f3 83 c3 01 75 03 90 02 05 89 fb 89 04 0a 83 c1 01 75 90 00 } //01 00 
		$a_03_1 = {35 30 89 e0 83 c4 06 ff 28 e8 90 01 01 ff ff ff c3 90 00 } //01 00 
		$a_01_2 = {30 46 6e c0 0f 6e 0b eb } //01 00 
		$a_01_3 = {64 8b 1d c0 00 00 00 eb } //00 00 
		$a_00_4 = {5d 04 00 } //00 22 
	condition:
		any of ($a_*)
 
}