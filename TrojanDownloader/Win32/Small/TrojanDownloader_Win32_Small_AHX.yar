
rule TrojanDownloader_Win32_Small_AHX{
	meta:
		description = "TrojanDownloader:Win32/Small.AHX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {71 64 2e 6e 65 74 6b 69 6c 6c 2e 63 6f 6d 2e 63 6e } //1 qd.netkill.com.cn
		$a_01_1 = {61 7d 7d 79 33 26 26 78 6d 27 67 6c 7d 62 60 65 65 27 6a 66 64 27 6a 67 26 79 7e 27 7d 71 7d } //1 a}}y3&&xm'gl}b`ee'jfd'jg&y~'}q}
		$a_03_2 = {6f 73 6f 66 74 5f 6c 6f 63 6b 00 00 25 75 00 00 43 3a 5c 90 09 08 00 6d 69 63 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}