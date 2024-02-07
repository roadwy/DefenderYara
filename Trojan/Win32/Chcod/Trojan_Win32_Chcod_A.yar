
rule Trojan_Win32_Chcod_A{
	meta:
		description = "Trojan:Win32/Chcod.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_1 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //01 00  GetWindowsDirectoryA
		$a_01_2 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //01 00  OpenProcessToken
		$a_01_3 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 41 } //01 00  RegisterServiceCtrlHandlerA
		$a_01_4 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //01 00  Accept-Language: zh-cn
		$a_01_5 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 73 68 6f 63 6b 77 61 76 65 2d 66 6c 61 73 68 2c 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 76 6e 64 2e 6d 73 2d 65 78 63 65 6c } //01 00  application/x-shockwave-flash, application/vnd.ms-excel
		$a_01_6 = {43 3a 5c 54 2e 69 6e 69 } //01 00  C:\T.ini
		$a_01_7 = {30 2e 30 2e 31 2e 31 } //01 00  0.0.1.1
		$a_01_8 = {83 c9 ff 33 c0 c6 } //01 00 
		$a_01_9 = {3c 2f 74 0d 84 c0 74 09 8a } //00 00 
	condition:
		any of ($a_*)
 
}