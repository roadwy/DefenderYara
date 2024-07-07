
rule TrojanDownloader_O97M_Emotet_PDEB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDEB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 7a 6f 6f 6d 70 69 78 65 6c 2e 63 6f 6d 2e 62 72 2f 77 70 2d 61 64 6d 69 6e 2f 71 48 53 2f } //1 ://zoompixel.com.br/wp-admin/qHS/
		$a_01_1 = {3a 2f 2f 6e 61 70 6f 6c 6e 69 2e 6d 65 2f 33 72 2f 75 46 2f } //1 ://napolni.me/3r/uF/
		$a_01_2 = {3a 2f 2f 68 6f 73 74 69 6e 67 31 30 37 30 36 38 2e 61 32 66 32 61 2e 6e 65 74 63 75 70 2e 6e 65 74 2f 63 61 72 65 65 72 2f 39 39 64 74 6a 57 67 51 45 6d 54 74 70 74 36 43 33 31 2f } //1 ://hosting107068.a2f2a.netcup.net/career/99dtjWgQEmTtpt6C31/
		$a_01_3 = {3a 2f 2f 73 74 65 6c 6c 61 72 73 75 6d 6d 69 74 2e 39 37 2e 64 6f 75 62 6c 65 2e 69 6e 2e 74 68 2f 61 73 73 65 74 73 2f 58 62 6d 65 62 51 52 73 55 56 48 4c 30 6a 2f } //1 ://stellarsummit.97.double.in.th/assets/XbmebQRsUVHL0j/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}