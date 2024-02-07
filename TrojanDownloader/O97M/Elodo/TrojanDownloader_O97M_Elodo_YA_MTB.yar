
rule TrojanDownloader_O97M_Elodo_YA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Elodo.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 20 3d 20 26 48 38 30 30 30 30 30 30 31 } //01 00  Const HKEY_CURRENT_USER = &H80000001
		$a_00_1 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 } //01 00  GetObject("winmgmts:\\" & strComputer
		$a_00_2 = {5c 72 6f 6f 74 5c 64 65 66 61 75 6c 74 3a 53 74 64 52 65 67 50 72 6f 76 } //01 00  \root\default:StdRegProv
		$a_02_3 = {53 74 72 52 65 76 65 72 73 65 28 22 90 02 15 2f 79 6c 2e 74 69 62 5c 5c 3a 73 70 22 20 2b 20 22 74 22 20 2b 20 22 74 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}