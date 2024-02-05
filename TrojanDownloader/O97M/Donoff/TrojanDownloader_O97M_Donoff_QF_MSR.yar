
rule TrojanDownloader_O97M_Donoff_QF_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QF!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 78 78 77 73 78 63 78 72 69 78 70 74 78 20 78 78 20 58 2f 65 78 3a 78 78 78 78 58 4a 78 53 43 72 78 69 70 78 74 78 20 78 22 22 78 25 78 7e 78 66 78 58 30 78 } //01 00 
		$a_03_1 = {45 6e 76 69 72 6f 6e 28 90 02 0a 28 22 90 0e 20 00 41 50 50 90 0e 20 00 44 41 54 41 90 0e 20 00 22 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}