
rule TrojanDownloader_O97M_Obfuse_AY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 41 4c 4c 28 22 75 72 6c 6d 6f 6e 22 2c 22 55 52 4c 44 6f 77 6e 6c 22 26 43 48 41 52 28 31 31 31 29 26 22 61 64 54 6f 46 69 6c 65 41 22 2c } //01 00  CALL("urlmon","URLDownl"&CHAR(111)&"adToFileA",
		$a_00_1 = {22 4a 4a 43 43 4a 4a 22 2c 30 2c 43 48 41 52 28 31 30 34 29 26 } //01 00  "JJCCJJ",0,CHAR(104)&
		$a_00_2 = {22 74 74 70 73 3a 2f 2f 72 65 62 72 61 6e 64 2e 6c 79 2f 69 65 6e 63 6c 69 35 31 62 61 74 22 } //01 00  "ttps://rebrand.ly/iencli51bat"
		$a_00_3 = {3d 45 58 45 43 28 22 43 3a 5c 50 52 4f 47 52 41 4d 44 41 54 41 5c 61 2e 62 61 74 22 29 } //00 00  =EXEC("C:\PROGRAMDATA\a.bat")
	condition:
		any of ($a_*)
 
}