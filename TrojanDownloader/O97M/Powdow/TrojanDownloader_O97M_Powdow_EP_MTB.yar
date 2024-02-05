
rule TrojanDownloader_O97M_Powdow_EP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.EP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 72 65 62 72 61 6e 64 2e 6c 79 2f 77 69 79 35 63 6d 30 } //01 00 
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}