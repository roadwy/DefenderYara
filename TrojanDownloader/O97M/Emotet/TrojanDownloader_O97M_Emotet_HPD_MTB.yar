
rule TrojanDownloader_O97M_Emotet_HPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.HPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 66 73 2e 64 6c 6c [0-20] 72 22 26 22 65 67 22 26 22 73 22 26 22 76 72 33 22 26 22 32 2e 65 22 26 22 78 22 26 22 65 [0-06] 57 22 26 22 69 6e 64 22 26 22 6f 22 26 22 77 22 26 22 73 [0-06] 53 22 26 22 79 73 57 22 26 22 6f 77 22 26 22 36 34 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}