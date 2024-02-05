
rule TrojanDownloader_O97M_Emotet_BOAJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BOAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 22 26 22 73 64 22 26 22 63 2e 70 22 26 22 6c 2f 73 22 26 22 6d 69 22 26 22 65 63 22 26 22 69 6f 2f 31 22 26 22 39 56 22 26 22 59 66 22 26 22 68 48 22 26 22 4c 70 2f } //00 00 
	condition:
		any of ($a_*)
 
}