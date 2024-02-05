
rule Trojan_Win32_Alureon_DP{
	meta:
		description = "Trojan:Win32/Alureon.DP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 43 43 43 4e 89 45 90 01 01 68 33 33 52 47 90 00 } //01 00 
		$a_01_1 = {b8 4e 46 4d 47 e8 } //01 00 
		$a_01_2 = {b8 4f 43 49 48 e8 } //01 00 
		$a_01_3 = {b8 42 50 4d 48 e8 } //01 00 
		$a_01_4 = {7c e6 ff 75 10 8b 55 18 8b 4d 14 8d 85 fc fe ff ff } //01 00 
		$a_01_5 = {c6 00 e9 83 e9 05 89 48 01 8d 45 f8 50 6a 05 } //01 00 
		$a_01_6 = {34 44 57 34 52 33 } //01 00 
		$a_01_7 = {73 75 62 64 65 6c 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}