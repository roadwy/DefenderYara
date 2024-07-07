
rule TrojanDownloader_Win32_QQHelper_D{
	meta:
		description = "TrojanDownloader:Win32/QQHelper.D,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {31 36 39 39 30 2e 63 6f 6d } //1 16990.com
		$a_01_2 = {62 69 7a 6d 64 2e 63 6e 2f 61 64 2f 41 44 53 65 72 76 69 63 65 2e 61 73 6d 78 } //1 bizmd.cn/ad/ADService.asmx
		$a_01_3 = {39 36 43 39 33 30 46 44 2d 41 45 39 34 2d 34 32 44 30 2d 42 36 33 38 2d 36 41 46 38 43 30 39 33 30 46 43 45 } //1 96C930FD-AE94-42D0-B638-6AF8C0930FCE
		$a_01_4 = {42 39 41 33 36 37 45 43 2d 34 44 45 35 2d 34 30 32 41 2d 38 37 43 46 2d 37 44 45 45 38 41 44 42 30 30 45 35 } //1 B9A367EC-4DE5-402A-87CF-7DEE8ADB00E5
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_8 = {43 72 65 61 74 65 53 65 72 76 69 63 65 41 } //1 CreateServiceA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}