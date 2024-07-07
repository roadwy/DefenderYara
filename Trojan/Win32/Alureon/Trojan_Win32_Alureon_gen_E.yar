
rule Trojan_Win32_Alureon_gen_E{
	meta:
		description = "Trojan:Win32/Alureon.gen!E,SIGNATURE_TYPE_PEHSTR,08 01 07 01 0f 00 00 "
		
	strings :
		$a_01_0 = {4d 44 35 48 61 73 68 20 66 75 6e 63 74 69 6f 6e 20 65 78 70 65 63 74 65 64 21 } //100 MD5Hash function expected!
		$a_01_1 = {48 65 78 44 65 63 6f 64 65 72 20 66 75 6e 63 74 69 6f 6e 20 65 78 70 65 63 74 65 64 21 } //100 HexDecoder function expected!
		$a_01_2 = {6b 65 79 2e 6c 6b 79 } //10 key.lky
		$a_01_3 = {73 65 74 75 70 33 2e 65 78 65 } //10 setup3.exe
		$a_01_4 = {5c 6e 6f 74 65 70 61 64 2e 65 78 65 2e 64 61 74 } //10 \notepad.exe.dat
		$a_01_5 = {5c 63 61 6c 63 2e 65 78 65 2e 64 61 74 } //10 \calc.exe.dat
		$a_01_6 = {44 65 63 72 79 70 74 } //10 Decrypt
		$a_01_7 = {53 4f 46 54 57 41 52 45 20 49 4e 53 54 41 4c 4c 41 54 49 4f 4e 3a 20 43 6f 6d 70 6f 6e 65 6e 74 73 20 62 75 6e 64 6c 65 64 20 69 6e 74 6f 20 74 68 65 20 73 6f 66 74 77 61 72 65 20 6d 61 79 20 72 65 70 6f 72 74 20 74 6f 20 4c 69 63 65 6e 73 6f 72 } //10 SOFTWARE INSTALLATION: Components bundled into the software may report to Licensor
		$a_01_8 = {23 33 32 37 37 30 } //10 #32770
		$a_01_9 = {44 63 72 79 70 74 44 6c 6c 2e 64 6c 6c } //10 DcryptDll.dll
		$a_01_10 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //1 Nullsoft Install System
		$a_01_11 = {49 74 20 6d 61 79 20 62 65 20 70 6f 73 73 69 62 6c 65 20 74 6f 20 73 6b 69 70 20 74 68 69 73 20 63 68 65 63 6b 20 75 73 69 6e 67 20 74 68 65 20 2f 4e 43 52 43 20 63 6f 6d 6d 61 6e 64 20 6c 69 6e 65 20 73 77 69 74 63 68 } //1 It may be possible to skip this check using the /NCRC command line switch
		$a_01_12 = {6d 6f 64 65 72 6e 2d 68 65 61 64 65 72 2e 62 6d 70 } //1 modern-header.bmp
		$a_01_13 = {73 74 61 72 74 6d 65 6e 75 2e 64 6c 6c } //1 startmenu.dll
		$a_01_14 = {6c 7a 6d 61 2e 65 78 65 } //1 lzma.exe
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=263
 
}