
rule TrojanDownloader_O97M_Emotet_ATPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ATPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 68 61 69 63 73 31 2e 6f 63 78 } //1 \haics1.ocx
		$a_01_1 = {5c 68 61 69 63 73 32 2e 6f 63 78 } //1 \haics2.ocx
		$a_01_2 = {5c 68 61 69 63 73 33 2e 6f 63 78 } //1 \haics3.ocx
		$a_03_3 = {75 72 6c 6d 6f 6e [0-03] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}