
rule TrojanDownloader_AndroidOS_DownSMS_A{
	meta:
		description = "TrojanDownloader:AndroidOS/DownSMS.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f 90 01 08 2f 73 72 76 2e 74 78 74 90 00 } //2
		$a_01_1 = {61 63 74 69 76 61 74 6f 72 2e 61 70 6b } //1 activator.apk
		$a_01_2 = {76 61 6c 24 77 61 6c 6c 70 61 70 65 72 4d 61 6e 61 67 65 72 } //1 val$wallpaperManager
		$a_01_3 = {2f 64 6f 77 6e 6c 6f 61 64 2f } //1 /download/
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}