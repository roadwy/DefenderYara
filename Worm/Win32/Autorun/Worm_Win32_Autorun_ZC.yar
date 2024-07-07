
rule Worm_Win32_Autorun_ZC{
	meta:
		description = "Worm:Win32/Autorun.ZC,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {21 6c 6f 67 6f 75 74 } //1 !logout
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 2f 45 78 65 63 75 74 69 6e 67 2e 2e 2e } //1 Downloading/Executing...
		$a_01_2 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 3b 20 55 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 65 6e 2d 55 53 3b 20 72 76 3a 31 2e 39 2e 32 2e 33 29 20 47 65 63 6b 6f 2f 32 30 31 30 30 34 30 31 20 46 69 72 65 66 6f 78 2f 33 2e 36 2e 33 } //1 Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3
		$a_01_3 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_01_4 = {25 61 70 70 64 61 74 61 25 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //2 %appdata%\svchost.exe
		$a_01_5 = {49 6e 66 65 63 74 65 64 20 52 65 6d 6f 76 61 62 6c 65 20 44 72 69 76 65 2e 2e } //2 Infected Removable Drive..
		$a_01_6 = {8a 04 0b f6 d0 88 01 8b c7 46 41 8d 78 01 8a 10 40 84 d2 75 f9 2b c7 3b f0 72 e2 8b 4d 08 5b 5f 88 14 0e } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=7
 
}