
rule Worm_Win32_VB_XA{
	meta:
		description = "Worm:Win32/VB.XA,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 00 77 00 69 00 6e 00 74 00 72 00 61 00 79 00 2e 00 76 00 62 00 70 00 } //1 \wintray.vbp
		$a_01_1 = {63 00 3a 00 5c 00 6e 00 65 00 74 00 2e 00 74 00 78 00 74 00 } //1 c:\net.txt
		$a_01_2 = {47 00 68 00 6f 00 73 00 74 00 2e 00 62 00 61 00 74 00 } //1 Ghost.bat
		$a_01_3 = {41 00 3a 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 45 00 58 00 45 00 } //1 A:\Explorer.EXE
		$a_01_4 = {41 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 2e 00 45 00 58 00 45 00 } //1 A:\WINDOWS.EXE
		$a_01_5 = {41 00 3a 00 5c 00 4e 00 65 00 74 00 48 00 6f 00 6f 00 64 00 2e 00 68 00 74 00 6d 00 } //1 A:\NetHood.htm
		$a_01_6 = {4b 00 61 00 56 00 33 00 30 00 30 00 58 00 50 00 } //1 KaV300XP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}