
rule Trojan_Win32_PSWStealer_WM_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.WM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f be 34 10 68 12 96 67 05 68 19 42 09 00 e8 90 01 04 83 c4 08 0f af f0 8b 4d 0c 03 4d fc 0f be 11 33 d6 8b 45 0c 03 45 fc 88 10 eb b6 90 00 } //0a 00 
		$a_02_1 = {30 ff ff ff 03 85 90 01 04 89 85 90 01 04 8b 8d 90 01 04 0f af 4d f4 89 8d 90 01 04 8b 95 90 01 04 0f af 95 90 01 04 89 95 90 01 04 8b 85 28 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}