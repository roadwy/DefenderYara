
rule Trojan_Win32_Exgectow_A{
	meta:
		description = "Trojan:Win32/Exgectow.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 e8 90 01 02 ff ff 89 45 fc 83 7d fc 00 74 0e ff 75 10 ff 75 0c ff 75 08 ff 55 fc eb 03 6a 01 58 c9 c2 0c 00 90 00 } //01 00 
		$a_03_1 = {e8 00 00 00 00 58 90 02 08 2b c3 90 02 08 89 45 90 02 08 9d 90 02 08 61 90 02 08 8b 45 90 02 08 8b 00 8b 00 89 45 90 00 } //01 00 
		$a_03_2 = {2d d2 13 40 00 8b 4d 90 02 08 2b c8 90 02 08 89 4d 90 02 08 8d 90 02 08 50 6a 40 b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}