
rule Trojan_Win32_CoinMiner_AC{
	meta:
		description = "Trojan:Win32/CoinMiner.AC,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 29 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {63 6d 64 20 2f 63 } //0a 00  cmd /c
		$a_00_1 = {73 63 20 73 74 61 72 74 20 } //0a 00  sc start 
		$a_01_2 = {68 3f 00 0f 00 33 db 53 53 ff 15 } //0a 00 
		$a_01_3 = {68 00 5c 26 05 ff d6 } //01 00 
		$a_00_4 = {68 74 74 70 3a 2f 2f 67 2d 73 2e 63 6f 6f 6c 2f 64 69 72 2e 70 68 70 } //01 00  http://g-s.cool/dir.php
		$a_02_5 = {68 74 74 70 3a 2f 2f 67 2d 73 2e 63 6f 6f 6c 2f 76 65 72 90 02 05 2e 70 68 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}