
rule TrojanDownloader_O97M_Emotet_PDS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 61 61 63 69 74 79 67 72 6f 75 70 2e 63 6f 6d 2f 6d 6f 72 64 61 63 69 74 79 2f 67 32 39 50 51 68 75 59 41 35 78 2f } //1 ://www.aacitygroup.com/mordacity/g29PQhuYA5x/
		$a_01_1 = {3a 2f 2f 61 63 74 69 76 69 64 61 64 65 73 2e 6c 61 66 6f 72 65 74 6c 61 6e 67 75 61 67 65 73 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 75 4b 4c 4d 77 51 77 77 6f 30 57 2f } //1 ://actividades.laforetlanguages.com/wp-admin/uKLMwQwwo0W/
		$a_01_2 = {3a 2f 2f 73 73 65 2d 73 74 75 64 69 6f 2e 63 6f 6d 2f 63 71 30 78 68 70 6a 2f 77 64 6b 74 6d 6c 6c 66 41 59 56 2f } //1 ://sse-studio.com/cq0xhpj/wdktmllfAYV/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}