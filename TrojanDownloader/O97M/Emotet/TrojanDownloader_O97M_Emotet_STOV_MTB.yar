
rule TrojanDownloader_O97M_Emotet_STOV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.STOV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 68 61 74 68 61 61 62 65 61 63 68 2e 63 6f 6d 2f 64 6f 63 75 6d 65 6e 74 73 2f 78 62 5a 78 58 69 2f } //1 ://hathaabeach.com/documents/xbZxXi/
		$a_01_1 = {3a 2f 2f 74 65 6b 73 74 69 6c 75 7a 6d 61 6e 67 6f 72 75 73 75 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 56 54 68 53 43 74 45 52 4d 35 48 6a 2f } //1 ://tekstiluzmangorusu.com/wp-admin/VThSCtERM5Hj/
		$a_01_2 = {3a 2f 2f 7a 68 69 76 69 72 2e 63 6f 6d 2f 77 70 2f 79 72 71 75 70 54 31 51 77 58 75 52 64 58 33 2f } //1 ://zhivir.com/wp/yrqupT1QwXuRdX3/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}