
rule TrojanDownloader_O97M_Levar_PV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Levar.PV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {43 61 6c 6c 20 53 68 65 6c 6c 28 22 22 22 22 20 26 20 6d 61 6e 6e 65 72 90 01 01 20 26 20 22 5c 55 6e 72 61 76 65 6c 5c 6c 75 61 2e 63 6d 64 90 00 } //01 00 
		$a_00_1 = {5c 55 6e 72 61 76 65 6c 5c 62 6f 6c 74 2e 6c 75 61 } //01 00  \Unravel\bolt.lua
		$a_00_2 = {4b 69 6c 6c 20 6d 61 6e 6e 65 72 34 20 2b 20 22 5c 75 6e 72 61 76 65 6c 2e 64 6f 63 } //01 00  Kill manner4 + "\unravel.doc
		$a_00_3 = {55 6e 53 74 6f 72 65 20 6d 61 6e 6e 65 72 34 20 2b 20 22 5c 75 6e 72 61 76 65 6c 2e 7a 69 70 } //01 00  UnStore manner4 + "\unravel.zip
		$a_00_4 = {3d 20 22 43 3a 5c 55 73 65 72 73 22 20 2b 20 22 5c 50 75 62 6c 69 63 } //01 00  = "C:\Users" + "\Public
		$a_00_5 = {43 61 6c 6c 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 6f 70 79 20 22 20 2b 20 6d 61 6e 6e 65 72 } //00 00  Call Shell("cmd /c copy " + manner
	condition:
		any of ($a_*)
 
}