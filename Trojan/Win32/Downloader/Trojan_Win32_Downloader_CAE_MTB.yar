
rule Trojan_Win32_Downloader_CAE_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {47 61 6d 65 5f 59 2e 65 78 65 } //1 Game_Y.exe
		$a_01_1 = {5f 47 65 74 44 65 63 72 79 70 74 50 72 6f 63 40 34 } //1 _GetDecryptProc@4
		$a_01_2 = {5f 47 65 74 45 6e 63 72 79 70 74 50 72 6f 63 40 34 } //1 _GetEncryptProc@4
		$a_01_3 = {5f 53 65 74 44 65 63 72 79 70 74 69 6f 6e 4b 65 79 40 34 } //1 _SetDecryptionKey@4
		$a_81_4 = {47 61 6d 65 2e 65 78 65 } //1 Game.exe
		$a_01_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 78 71 79 31 2e 63 6f 6d 2f 6e 65 77 73 2e 68 74 6d 6c } //1 http://www.jxqy1.com/news.html
		$a_01_6 = {74 72 61 63 65 2e 6c 6f 67 } //1 trace.log
		$a_01_7 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_8 = {68 74 74 70 3a 2f 2f 6a 78 2e 6b 69 6e 67 73 6f 66 74 2e 63 6f 6d 2f 74 61 6e 2e 73 68 74 6d 6c } //1 http://jx.kingsoft.com/tan.shtml
		$a_01_9 = {77 77 77 2e 6a 78 6f 6e 6c 69 6e 65 2e 6e 65 74 } //1 www.jxonline.net
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}