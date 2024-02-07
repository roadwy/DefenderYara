
rule TrojanDownloader_O97M_Powdow_KG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 22 22 68 74 74 70 3a 2f 2f 33 2e 36 35 2e 32 2e 31 33 39 2f 72 65 61 64 2f 4c 74 72 77 6d 70 66 67 76 62 6b 2e 65 78 65 22 22 20 2d 4f 75 74 46 69 6c 65 } //00 00  Invoke-WebRequest -Uri ""http://3.65.2.139/read/Ltrwmpfgvbk.exe"" -OutFile
	condition:
		any of ($a_*)
 
}