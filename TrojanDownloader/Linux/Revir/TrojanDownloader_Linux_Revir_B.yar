
rule TrojanDownloader_Linux_Revir_B{
	meta:
		description = "TrojanDownloader:Linux/Revir.B,SIGNATURE_TYPE_MACHOHSTR_EXT,09 00 08 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 6a 70 67 } //01 00 
		$a_01_1 = {2e 70 64 66 } //01 00 
		$a_00_2 = {73 74 61 72 74 21 } //01 00 
		$a_01_3 = {2f 74 6d 70 2f } //01 00 
		$a_01_4 = {6f 70 65 6e 20 73 65 6c 66 } //05 00 
		$a_03_5 = {c7 44 24 04 ff 01 00 00 90 02 10 89 04 24 e8 90 01 02 00 00 c7 04 24 90 00 } //05 00 
		$a_01_6 = {01 ff 7e a3 ab 78 48 00 00 41 38 76 1e f4 48 00 01 39 } //00 00 
	condition:
		any of ($a_*)
 
}