
rule TrojanDownloader_BAT_Eves_A{
	meta:
		description = "TrojanDownloader:BAT/Eves.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 37 32 62 53 49 4c 6c 7a 43 77 58 42 53 72 51 } //01 00 
		$a_01_1 = {51 69 63 6f 77 49 47 4f 4e 79 64 46 45 76 } //00 00 
		$a_00_2 = {78 } //67 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Eves_A_2{
	meta:
		description = "TrojanDownloader:BAT/Eves.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 00 73 00 61 00 73 00 73 00 33 00 32 00 33 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_02_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 39 00 38 00 2e 00 35 00 30 00 2e 00 31 00 35 00 39 00 2e 00 31 00 35 00 35 00 2f 00 90 02 06 2f 00 90 02 05 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}