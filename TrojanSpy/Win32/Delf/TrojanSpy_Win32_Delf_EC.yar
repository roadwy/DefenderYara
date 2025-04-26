
rule TrojanSpy_Win32_Delf_EC{
	meta:
		description = "TrojanSpy:Win32/Delf.EC,SIGNATURE_TYPE_PEHSTR,29 00 29 00 08 00 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //10 explorerbar
		$a_01_1 = {5c 53 79 73 74 65 6d 5c 73 63 72 65 65 6e 2e 6a 70 67 } //10 \System\screen.jpg
		$a_01_2 = {5c 53 79 73 74 65 6d 5c 73 76 63 68 6f 73 74 73 2e 65 78 65 } //10 \System\svchosts.exe
		$a_01_3 = {5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 73 2e 65 78 65 } //10 \System32\svchosts.exe
		$a_01_4 = {44 61 76 69 7a 69 6e 58 20 53 63 72 65 65 6e 4c 6f 67 67 65 72 } //1 DavizinX ScreenLogger
		$a_01_5 = {64 61 76 69 7a 69 6e 78 74 6f 6f 6c 73 40 64 61 76 69 69 7a 6e 78 2e 63 6f 6d } //1 davizinxtools@daviiznx.com
		$a_01_6 = {44 61 76 69 7a 69 6e 58 4b 65 79 6c 6f 67 67 65 72 40 64 61 76 69 7a 69 6e 78 2e 63 6f 6d } //1 DavizinXKeylogger@davizinx.com
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 64 61 76 69 7a 69 6e 78 2e 63 6f 6d 2f 64 61 76 69 7a 69 6e 2e 70 68 70 } //1 http://www.davizinx.com/davizin.php
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=41
 
}