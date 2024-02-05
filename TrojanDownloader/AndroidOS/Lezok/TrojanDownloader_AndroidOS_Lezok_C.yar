
rule TrojanDownloader_AndroidOS_Lezok_C{
	meta:
		description = "TrojanDownloader:AndroidOS/Lezok.C,SIGNATURE_TYPE_DEXHSTR_EXT,19 00 19 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 69 77 74 69 67 65 72 2e 70 6c 75 67 69 6e } //05 00 
		$a_00_1 = {64 6f 77 6e 6c 6f 61 64 46 69 6c 65 42 65 66 6f 72 65 45 78 65 63 75 74 65 } //05 00 
		$a_00_2 = {63 6f 6e 76 65 72 74 55 72 6c 54 6f 4c 6f 63 61 6c 46 69 6c 65 } //05 00 
		$a_00_3 = {75 70 6c 6f 61 64 4d 61 75 53 74 61 74 75 73 } //00 00 
	condition:
		any of ($a_*)
 
}