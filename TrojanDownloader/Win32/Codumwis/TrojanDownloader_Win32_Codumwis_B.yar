
rule TrojanDownloader_Win32_Codumwis_B{
	meta:
		description = "TrojanDownloader:Win32/Codumwis.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 6f 72 53 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 33 36 30 } //1 MicorSoft\Windows\CurrentVersion\Uninstall\360
		$a_01_1 = {69 6e 74 2e 64 70 6f 6f 6c 2e 73 69 6e 61 2e 63 6f 6d 2e 63 6e 2f 69 70 6c 6f 6f 6b 75 70 2f 69 70 6c 6f 6f 6b 75 70 2e 70 68 70 } //1 int.dpool.sina.com.cn/iplookup/iplookup.php
		$a_01_2 = {68 74 74 70 3a 2f 2f 74 2e 63 6e } //1 http://t.cn
		$a_01_3 = {53 6f 48 75 56 41 5f 34 2e 32 2e 30 2e 31 36 2d 63 32 30 34 39 30 30 30 30 33 2d 6e 67 2d 6e 74 69 2d 74 70 2d 73 2d 78 2e 65 78 65 } //1 SoHuVA_4.2.0.16-c204900003-ng-nti-tp-s-x.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}