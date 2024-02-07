
rule TrojanDownloader_O97M_Kriof_A{
	meta:
		description = "TrojanDownloader:O97M/Kriof.A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2d 77 69 6e 64 6f 77 20 68 69 64 64 65 6e 20 2d 65 6e 63 } //01 00  -window hidden -enc
		$a_00_1 = {43 72 69 74 69 63 61 6c 20 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 20 45 72 72 6f 72 } //01 00  Critical Microsoft Office Error
		$a_00_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //01 00  powershell.exe
		$a_00_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00  Sub AutoOpen()
		$a_00_4 = {4a 41 41 78 41 43 41 41 50 51 41 67 41 43 63 41 4a 41 42 6a 41 43 41 41 50 51 41 67 41 43 } //00 00  JAAxACAAPQAgACcAJABjACAAPQAgAC
		$a_00_5 = {5d 04 00 00 } //25 65 
	condition:
		any of ($a_*)
 
}