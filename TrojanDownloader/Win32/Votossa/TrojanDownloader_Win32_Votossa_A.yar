
rule TrojanDownloader_Win32_Votossa_A{
	meta:
		description = "TrojanDownloader:Win32/Votossa.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 65 74 6f 70 65 6e 61 20 6f 6b 00 } //01 00 
		$a_01_1 = {63 6f 6e 6e 65 63 74 61 20 6f 6b 00 } //01 00 
		$a_01_2 = {72 65 71 31 20 6f 6b 00 } //01 00 
		$a_01_3 = {68 65 61 64 31 20 6f 6b 00 } //01 00 
		$a_01_4 = {32 30 30 20 6f 6b 00 } //01 00 
		$a_01_5 = {50 45 20 6e 6f 74 20 6f 6b 00 } //01 00 
		$a_01_6 = {70 65 20 76 61 6c 69 64 00 } //01 00 
		$a_01_7 = {69 6e 69 74 69 61 6c 69 7a 65 64 20 6f 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}