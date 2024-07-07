
rule TrojanDownloader_O97M_Malgent_C{
	meta:
		description = "TrojanDownloader:O97M/Malgent.C,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {3d 20 45 6e 76 69 72 6f 6e 24 28 52 65 70 6c 61 63 65 28 22 41 70 70 23 23 44 61 23 23 74 61 22 2c 20 22 23 23 22 2c 20 22 22 29 29 } //1 = Environ$(Replace("App##Da##ta", "##", ""))
		$a_00_1 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 23 23 74 70 23 23 3a 23 23 2f 23 23 2f } //1 = Replace("ht##tp##:##/##/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}