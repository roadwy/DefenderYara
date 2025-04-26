
rule TrojanDownloader_O97M_Emotet_RPET_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RPET!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5c 57 69 6e 64 6f 77 73 5c [0-05] 53 79 73 57 6f 77 36 34 5c [0-0f] 52 45 54 55 52 4e [0-05] 68 74 74 70 3a 2f 2f [0-05] 68 74 74 70 73 3a 2f 2f [0-7f] 2e 63 6f 6d [0-7f] 2e 63 6f 6d [0-7f] 2e 63 6f 6d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}