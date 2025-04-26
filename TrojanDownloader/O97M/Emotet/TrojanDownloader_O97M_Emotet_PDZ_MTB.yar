
rule TrojanDownloader_O97M_Emotet_PDZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 79 73 57 6f 77 36 34 5c [0-05] 5c 57 69 6e 64 6f 77 73 5c [0-1f] 5c 72 64 73 2e 6f 63 78 [0-06] 5c 72 64 73 2e 6f 63 78 [0-05] 72 22 26 22 65 67 22 26 22 73 76 22 26 22 72 33 22 26 22 32 2e 65 22 26 22 78 65 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}