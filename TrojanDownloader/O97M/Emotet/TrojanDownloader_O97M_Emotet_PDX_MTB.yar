
rule TrojanDownloader_O97M_Emotet_PDX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 65 67 73 76 72 33 32 2e 65 78 65 90 02 03 5c 57 69 6e 64 6f 77 73 5c 90 02 03 53 79 73 57 6f 77 36 34 5c 90 02 0f 5c 65 6e 2e 6f 63 78 90 00 } //1
		$a_03_1 = {72 65 67 73 76 72 33 32 2e 65 78 65 90 02 03 53 79 73 57 6f 77 36 34 5c 90 02 0f 22 4a 4a 43 43 42 42 22 90 02 06 5c 77 6e 2e 6f 63 78 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}