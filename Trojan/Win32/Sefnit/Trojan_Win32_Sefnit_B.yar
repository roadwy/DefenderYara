
rule Trojan_Win32_Sefnit_B{
	meta:
		description = "Trojan:Win32/Sefnit.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 7c 24 1c 49 8b 04 8e 35 90 01 04 89 04 8f 83 f9 00 75 ef 90 00 } //02 00 
		$a_03_1 = {81 ec 18 06 00 00 90 17 03 01 07 09 e9 c7 45 fc 01 00 00 00 c7 85 90 01 04 01 00 00 00 90 00 } //02 00 
		$a_03_2 = {83 c4 1c 58 ff 25 90 01 04 90 09 05 00 a3 90 1b 00 90 00 } //01 00 
		$a_01_3 = {b8 01 40 00 80 5d e9 } //01 00 
		$a_03_4 = {55 81 2c 24 90 01 04 6a 90 09 02 00 6a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}