
rule Trojan_Win32_TurlaCarbonInstaller_B{
	meta:
		description = "Trojan:Win32/TurlaCarbonInstaller.B,SIGNATURE_TYPE_PEHSTR,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {70 00 69 00 70 00 65 00 5c 00 63 00 6f 00 6d 00 6d 00 63 00 74 00 72 00 6c 00 64 00 65 00 76 00 } //1 pipe\commctrldev
		$a_01_1 = {70 00 69 00 70 00 65 00 5c 00 63 00 6f 00 6d 00 6d 00 73 00 65 00 63 00 64 00 65 00 76 00 } //1 pipe\commsecdev
		$a_01_2 = {69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //1 installer.exe
		$a_01_3 = {43 6f 75 6c 64 20 6e 6f 74 20 64 65 6c 65 74 65 20 7b 7d 5c 7b 7d 2e 73 79 73 } //1 Could not delete {}\{}.sys
		$a_01_4 = {69 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //2 installer.pdb
		$a_01_5 = {2f 00 50 00 55 00 42 00 2f 00 68 00 6f 00 6d 00 65 00 2e 00 68 00 74 00 6d 00 6c 00 } //2 /PUB/home.html
		$a_01_6 = {63 00 68 00 65 00 61 00 70 00 69 00 6e 00 66 00 6f 00 6d 00 65 00 64 00 69 00 63 00 61 00 6c 00 39 00 39 00 2e 00 6e 00 65 00 74 00 } //2 cheapinfomedical99.net
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=8
 
}