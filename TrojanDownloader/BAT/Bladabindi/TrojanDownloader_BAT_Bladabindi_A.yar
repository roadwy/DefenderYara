
rule TrojanDownloader_BAT_Bladabindi_A{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {1d 28 05 00 00 0a 72 90 01 01 00 00 70 7e 03 00 00 04 72 90 01 01 00 00 70 28 06 00 00 0a 17 73 0b 00 00 0a 0b 28 0c 00 00 0a 6f 0d 00 00 0a 28 0e 00 00 0a 90 00 } //01 00 
		$a_00_1 = {00 6f 6b 2e 65 78 65 00 } //01 00 
		$a_00_2 = {6c 69 6e 6b 73 20 53 74 61 72 74 55 50 20 68 61 73 68 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Bladabindi_A_2{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {de 00 1d 28 90 01 04 72 90 01 04 7e 90 01 04 72 90 01 04 28 90 00 } //01 00 
		$a_03_1 = {11 08 14 72 90 01 04 16 8d 01 00 00 01 14 14 14 28 90 01 04 14 72 90 01 04 18 8d 01 00 00 01 90 00 } //01 00 
		$a_00_2 = {00 6f 6b 2e 65 78 65 00 } //01 00 
		$a_00_3 = {6c 69 6e 6b 73 20 53 74 61 72 74 55 50 20 68 61 73 68 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Bladabindi_A_3{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 90 01 02 49 00 6e 00 76 00 6f 00 6b 00 65 00 90 09 40 00 90 02 08 90 03 08 0a 54 00 72 00 75 00 65 00 46 00 61 00 6c 00 73 00 65 00 90 01 02 90 1e 01 00 00 90 1e 01 00 00 90 1e 01 00 00 90 1e 01 00 00 90 1e 01 00 00 90 1e 01 00 00 90 02 04 90 01 02 5c 00 90 01 02 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}