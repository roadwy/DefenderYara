
rule TrojanDownloader_O97M_Emotet_JPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.JPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6b 79 74 6b 2e 64 6c 6c [0-08] 5c 6b 79 74 6b 2e 64 6c 6c [0-05] 72 22 26 22 65 67 22 26 22 73 76 22 26 22 72 33 22 26 22 32 2e 65 78 65 [0-05] 5c 57 22 26 22 69 22 26 22 6e 64 6f 22 26 22 77 73 5c [0-05] 53 79 73 22 26 22 57 6f 77 22 26 22 36 34 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}