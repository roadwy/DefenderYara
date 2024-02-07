
rule TrojanDownloader_O97M_Emotet_VSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 62 62 69 77 6a 64 66 2e 76 62 73 } //01 00  c:\programdata\bbiwjdf.vbs
		$a_01_1 = {6c 61 62 6c 61 63 65 28 64 66 6a 6f 6c 65 69 68 64 78 64 6e 2c 22 47 77 65 69 22 2c 22 22 29 29 } //00 00  lablace(dfjoleihdxdn,"Gwei",""))
	condition:
		any of ($a_*)
 
}