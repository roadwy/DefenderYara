
rule TrojanDownloader_Win32_Adload_CC{
	meta:
		description = "TrojanDownloader:Win32/Adload.CC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 30 75 00 00 ff 15 90 01 04 8b 85 e8 ea ff ff 83 c6 02 e9 6d ff ff ff b8 90 01 04 c3 33 db 53 e8 90 01 04 68 40 1f 00 00 ff 15 90 00 } //1
		$a_01_1 = {2e 62 63 6a 6a 67 63 2e 63 6f 6d } //1 .bcjjgc.com
		$a_01_2 = {5c 47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 31 5c } //1 \GameVersionUpdate1\
		$a_01_3 = {5c 57 69 6e 64 6f 77 73 20 4e 54 5c 73 6d 73 5f 6c 6f 67 2e 74 78 74 } //1 \Windows NT\sms_log.txt
		$a_01_4 = {2f 73 74 61 74 2e 77 61 6d 6d 65 2e 63 6e 2f 43 38 43 2f 67 6c 2f 63 6e 7a 7a } //1 /stat.wamme.cn/C8C/gl/cnzz
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}