
rule TrojanDownloader_O97M_Powdow_RVN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 61 73 64 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  Set asd = CreateObject("WScript.Shell")
		$a_01_1 = {61 73 64 2e 52 75 6e 20 28 41 6d 72 61 44 58 29 } //01 00  asd.Run (AmraDX)
		$a_01_2 = {41 6d 72 61 44 58 20 3d 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 50 20 2d 73 74 61 20 2d 77 20 31 20 2d 65 6e 63 20 20 53 51 42 6d 41 43 67 41 4a 41 42 51 41 46 4d 41 56 67 22 } //01 00  AmraDX = "powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVg"
		$a_01_3 = {41 75 74 6f 43 6c 6f 73 65 28 29 0d 0a 20 20 20 20 41 5a 78 } //00 00 
	condition:
		any of ($a_*)
 
}