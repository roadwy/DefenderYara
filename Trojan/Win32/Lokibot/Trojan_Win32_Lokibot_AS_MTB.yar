
rule Trojan_Win32_Lokibot_AS_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 8b 1d c0 00 00 00 83 fb 00 74 90 01 01 eb 90 00 } //01 00 
		$a_03_1 = {89 e0 83 c4 06 ff 28 e8 90 01 02 ff ff c3 90 00 } //01 00 
		$a_03_2 = {8b 04 0a 01 f3 0f 6e c0 0f 6e 0b 0f ef c1 51 e9 90 01 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}