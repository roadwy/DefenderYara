
rule TrojanDownloader_Win32_Nythug_A{
	meta:
		description = "TrojanDownloader:Win32/Nythug.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //10 Nullsoft Install System
		$a_01_1 = {5c 45 78 65 63 50 72 69 2e 64 6c 6c } //10 \ExecPri.dll
		$a_01_2 = {68 74 74 70 3a 2f 2f 73 65 61 68 61 77 6b 31 37 2e 63 6f 2e 63 63 2f } //1 http://seahawk17.co.cc/
		$a_01_3 = {68 74 74 70 3a 2f 2f 73 77 69 66 74 78 2e 63 6f 2e 63 63 2f 6a 73 6b 35 65 2f } //1 http://swiftx.co.cc/jsk5e/
		$a_01_4 = {68 74 74 70 3a 2f 2f 66 72 69 73 6b 79 6c 6f 76 65 2e 63 6f 2e 63 63 2f } //1 http://friskylove.co.cc/
		$a_01_5 = {68 74 74 70 3a 2f 2f 32 31 37 2e 31 31 34 2e 32 31 35 2e 32 31 31 2f } //1 http://217.114.215.211/
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=21
 
}