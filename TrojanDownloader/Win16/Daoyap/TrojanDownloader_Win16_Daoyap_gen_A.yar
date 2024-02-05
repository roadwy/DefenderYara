
rule TrojanDownloader_Win16_Daoyap_gen_A{
	meta:
		description = "TrojanDownloader:Win16/Daoyap.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f } //01 00 
		$a_00_1 = {73 61 76 65 74 6f 66 69 6c 65 } //01 00 
		$a_00_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00 
		$a_00_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 64 6f 64 62 2e 53 74 72 65 61 6d 22 29 } //01 00 
		$a_00_4 = {70 61 79 6c 6f 61 64 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}