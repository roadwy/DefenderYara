
rule TrojanDownloader_O97M_Emotet_ALPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ALPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 74 72 75 73 74 74 72 61 6e 73 70 6f 72 74 2d 65 67 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 72 70 68 44 66 7a 62 73 2f } //1 ://trusttransport-eg.com/wp-admin/rphDfzbs/
		$a_01_1 = {3a 2f 2f 74 68 75 65 78 65 76 61 6e 70 68 6f 6e 67 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 46 36 4a 52 4e 2f } //1 ://thuexevanphong.com/wp-content/F6JRN/
		$a_01_2 = {3a 2f 2f 74 68 69 73 69 73 65 6c 69 7a 61 62 65 74 68 6a 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 71 65 67 31 36 45 5a 77 53 5a 79 32 2f } //1 ://thisiselizabethj.com/wp-content/qeg16EZwSZy2/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}