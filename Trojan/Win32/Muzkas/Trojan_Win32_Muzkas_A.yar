
rule Trojan_Win32_Muzkas_A{
	meta:
		description = "Trojan:Win32/Muzkas.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 f8 0a 75 1c 68 bc 02 00 00 e8 b9 1b ff ff } //02 00 
		$a_01_1 = {ff 13 50 ff 13 8b f0 8d 55 bc } //02 00 
		$a_01_2 = {ff 51 74 8b 4d fc ba 09 00 00 00 8b 03 8b 30 ff 56 0c 83 7d e4 00 74 61 } //01 00 
		$a_01_3 = {69 65 5f 67 75 76 65 6e 6c 69 6b 5f 70 6c 75 67 69 6e } //01 00 
		$a_01_4 = {73 65 63 75 72 69 74 79 5c 2e 6a 70 67 } //00 00 
	condition:
		any of ($a_*)
 
}