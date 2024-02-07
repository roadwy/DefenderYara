
rule TrojanDownloader_O97M_Donoff_PF{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PF,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 56 42 41 2e 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 4d 69 63 72 6f 73 6f 66 74 5c 45 78 63 65 6c 5c } //01 00  = VBA.Environ("AppData") & "\Microsoft\Excel\
		$a_00_1 = {3d 20 22 75 70 64 61 74 65 2e 74 78 74 } //01 00  = "update.txt
		$a_02_2 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 90 02 10 2c 20 32 90 00 } //01 00 
		$a_02_3 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 28 22 63 73 63 72 69 70 74 20 2f 2f 45 3a 6a 73 63 72 69 70 74 20 22 20 26 20 90 02 10 29 2c 20 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}