
rule TrojanProxy_Win32_Kabwall_A{
	meta:
		description = "TrojanProxy:Win32/Kabwall.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {bb 05 00 00 00 e8 90 01 03 ff b8 09 00 00 00 e8 90 01 03 ff 8b f0 8d 55 f8 8b c6 e8 90 01 03 ff 8b 55 f8 8d 45 fc e8 90 01 03 ff 4b 75 d7 90 00 } //01 00 
		$a_03_1 = {8d 7b 0a a5 a5 a5 a5 5f 5e 89 73 04 66 c7 43 08 3c 00 53 e8 90 01 03 ff 84 c0 74 08 3c 06 0f 85 90 01 01 00 00 00 90 00 } //01 00 
		$a_03_2 = {84 c0 75 29 ff 45 c4 83 7d c4 1e 7e 0d 8b 45 fc e8 90 01 03 ff e9 90 01 02 00 00 68 88 13 00 00 e8 90 01 03 ff 8b 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}