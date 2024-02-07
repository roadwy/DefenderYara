
rule TrojanDownloader_O97M_Remcos_KI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Remcos.KI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 22 22 68 74 74 70 73 3a 2f 2f 74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 71 49 4e 44 34 45 2f 52 63 68 6e 70 63 2e 65 78 65 22 22 20 2d 4f 75 74 46 69 6c 65 } //00 00  Invoke-WebRequest -Uri ""https://transfer.sh/get/qIND4E/Rchnpc.exe"" -OutFile
	condition:
		any of ($a_*)
 
}