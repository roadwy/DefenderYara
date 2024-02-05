
rule TrojanDownloader_O97M_Powdow_RP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6c 6f 6c 65 61 73 73 74 72 69 6e 67 64 69 6d 68 6f 6c 6c 65 61 73 69 6e 74 65 67 65 72 64 69 6d 69 61 73 69 6e 74 65 67 65 72 64 69 6d 68 6f 6c 65 6c 68 6f 6c 6c 65 31 31 31 31 31 68 6f 6c 65 6c 66 6f 72 69 31 74 6f 6c 65 6e 68 6c 6f 6c 65 73 74 65 70 32 68 6f 6c 65 6c 68 6f 6c 65 6c 63 68 72 63 6c 6e 67 68 6d 69 64 68 6c 6f 6c 65 69 32 32 39 6e 65 78 74 68 65 6c 6c 6f 68 6f 6c 65 6c 65 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}