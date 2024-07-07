
rule TrojanSpy_AndroidOS_Lanucher_A{
	meta:
		description = "TrojanSpy:AndroidOS/Lanucher.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 6c 6f 63 6b 20 74 68 65 20 73 6d 73 20 62 65 61 63 75 73 65 20 69 74 20 63 6f 6e 74 61 69 6e 20 74 68 65 20 74 65 6d 70 20 62 6c 6f 63 6b 20 6e 75 6d } //1 block the sms beacuse it contain the temp block num
		$a_01_1 = {56 45 44 49 4f 5f 44 4f 57 4e 4c 4f 41 44 5f 46 49 4c 45 5f 50 41 54 48 } //1 VEDIO_DOWNLOAD_FILE_PATH
		$a_01_2 = {42 67 53 65 72 76 69 63 65 2e 6a 61 76 61 } //1 BgService.java
		$a_01_3 = {56 65 64 69 6f 57 65 62 56 69 65 77 41 63 74 69 76 69 74 79 } //1 VedioWebViewActivity
		$a_01_4 = {76 65 64 69 6f 5f 64 6f 77 6e 6c 6f 61 64 5f 6c 69 6e 6b } //1 vedio_download_link
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}