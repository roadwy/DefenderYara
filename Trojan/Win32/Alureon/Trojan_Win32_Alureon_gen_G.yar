
rule Trojan_Win32_Alureon_gen_G{
	meta:
		description = "Trojan:Win32/Alureon.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 0b 00 00 "
		
	strings :
		$a_01_0 = {48 65 78 44 65 63 6f 64 65 72 00 48 65 78 45 6e 63 6f 64 65 72 00 4c 6f 61 64 53 74 72 00 4d 44 35 48 61 73 68 00 } //1 效䑸捥摯牥䠀硥湅潣敤r潌摡瑓r䑍䠵獡h
		$a_01_1 = {44 63 72 79 70 74 44 6c 6c 2e 64 6c 6c } //1 DcryptDll.dll
		$a_01_2 = {6e 6f 74 65 70 61 64 2e 65 78 65 2e 64 61 74 } //1 notepad.exe.dat
		$a_01_3 = {63 61 6c 63 2e 65 78 65 2e 64 61 74 } //1 calc.exe.dat
		$a_01_4 = {66 72 65 65 62 73 64 2e 65 78 65 2e 64 61 74 } //1 freebsd.exe.dat
		$a_01_5 = {6c 7a 6d 61 2e 65 78 65 } //1 lzma.exe
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 56 69 64 65 6f 50 6f 72 6e } //1 Software\VideoPorn
		$a_01_7 = {6c 69 6e 75 78 00 46 46 46 00 44 65 63 72 79 70 74 } //1
		$a_01_8 = {53 4f 46 54 57 41 52 45 20 49 4e 53 54 41 4c 4c 41 54 49 4f 4e 3a 20 43 6f 6d 70 6f 6e 65 6e 74 73 20 62 75 6e 64 6c 65 64 20 69 6e 74 6f 20 74 68 65 20 73 6f 66 74 77 61 72 65 20 6d 61 79 20 72 65 70 6f 72 74 20 74 6f 20 4c 69 63 65 6e 73 6f 72 } //1 SOFTWARE INSTALLATION: Components bundled into the software may report to Licensor
		$a_01_9 = {cf d0 ce c3 d0 c0 cc cc cd ce c3 ce 20 ce c1 c5 d1 cf c5 d7 c5 cd c8 df 3a 20 cf f0 ee e3 f0 e0 ec ec ed ee e5 20 ee e1 e5 f1 ef e5 f7 e5 ed e8 e5 20 f1 ee e4 e5 f0 e6 e8 f2 20 ea ee ec ef ee ed e5 ed f2 fb 20 ef e5 f0 e5 e4 e0 fe f9 e8 e5 } //1
		$a_01_10 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //1 Nullsoft Install System
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=7
 
}