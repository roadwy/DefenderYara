
rule TrojanDownloader_O97M_EncDoc_SMS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SMS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 41 52 54 49 43 20 3d 20 22 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 22 } //1 KARTIC = "://www.bitly.com/"
		$a_01_1 = {54 41 65 63 20 3d 20 22 } //1 TAec = "
		$a_01_2 = {54 59 69 6e 67 20 3d 20 22 } //1 TYing = "
		$a_01_3 = {54 49 54 41 54 20 3d 20 54 41 65 63 20 2b 20 54 59 69 6e 67 } //1 TITAT = TAec + TYing
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}