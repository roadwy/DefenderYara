
rule TrojanDownloader_O97M_Powdow_SFS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SFS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 4f 57 45 52 73 68 45 6c 6c 2e 45 78 45 20 77 47 65 74 20 68 74 74 70 73 3a 2f 2f 61 72 74 75 72 6b 61 72 6f 6c 63 7a 61 6b 73 68 69 6f 6c 61 2e 63 6f 6d 2f 7a 61 73 61 2f 66 59 69 41 32 32 65 58 70 55 54 54 37 75 50 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}