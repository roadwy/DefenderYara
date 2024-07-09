
rule TrojanDownloader_O97M_Adnel_E{
	meta:
		description = "TrojanDownloader:O97M/Adnel.E,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 20 69 69 69 4f 49 48 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 74 73 61 70 2f 2f 3a 70 22 29 20 2b 20 6f 6f 75 69 6a 69 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 ?? ?? ?? ?? ?? ?? ?? ?? 3d 69 3f 70 22 29 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}