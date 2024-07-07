
rule TrojanDownloader_O97M_Emotet_AIPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AIPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6d 69 63 72 6f 6c 65 6e 74 2e 63 6f 6d 2f 61 64 6d 69 6e 2f 6b 4d 34 34 32 62 64 4d 4c 4c 4d 51 31 71 4a 65 35 2f } //1 ://microlent.com/admin/kM442bdMLLMQ1qJe5/
		$a_01_1 = {3a 2f 2f 6e 65 6f 65 78 63 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 73 72 4e 30 78 59 67 6d 2f } //1 ://neoexc.com/cgi-bin/srN0xYgm/
		$a_01_2 = {3a 2f 2f 6f 6e 67 2d 68 61 6e 61 6e 65 6c 2e 6f 72 67 2f 50 41 51 55 45 53 2f 62 50 69 41 32 6c 36 66 6f 6a 37 6b 6a 4e 2f } //1 ://ong-hananel.org/PAQUES/bPiA2l6foj7kjN/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}