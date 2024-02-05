
rule TrojanDownloader_O97M_Emotet_PDEH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDEH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 22 26 22 72 6c 22 26 22 61 2e 65 22 26 22 73 2f 74 22 26 22 6d 22 26 22 70 2f 76 22 26 22 69 39 22 26 22 38 59 22 26 22 45 51 22 26 22 71 2f } //01 00 
		$a_01_1 = {6d 22 26 22 2f 69 6d 22 26 22 61 67 22 26 22 65 73 2f 47 22 26 22 47 31 22 26 22 64 38 22 26 22 61 6e 2f } //00 00 
	condition:
		any of ($a_*)
 
}