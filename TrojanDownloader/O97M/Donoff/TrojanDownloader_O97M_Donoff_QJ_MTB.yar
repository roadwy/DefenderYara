
rule TrojanDownloader_O97M_Donoff_QJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 73 73 22 20 2b 20 22 65 63 22 20 2b 20 22 6f 72 50 5f 22 20 2b 20 22 32 33 6e 69 57 22 20 2b 20 22 3a 32 22 20 2b 20 22 76 6d 69 22 20 2b 20 22 63 5c 74 22 20 2b 20 22 6f 6f 72 3a 22 20 2b 20 22 73 74 6d 22 20 2b 20 22 67 6d 6e 22 20 2b 20 22 69 77 22 } //2 "ss" + "ec" + "orP_" + "23niW" + ":2" + "vmi" + "c\t" + "oor:" + "stm" + "gmn" + "iw"
	condition:
		((#a_01_0  & 1)*2) >=2
 
}