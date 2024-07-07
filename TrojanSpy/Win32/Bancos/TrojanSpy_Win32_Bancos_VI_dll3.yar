
rule TrojanSpy_Win32_Bancos_VI_dll3{
	meta:
		description = "TrojanSpy:Win32/Bancos.VI!dll3,SIGNATURE_TYPE_PEHSTR,07 00 07 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //1 Software\Borland\Delphi
		$a_01_1 = {67 65 74 73 65 72 76 62 79 70 6f 72 74 } //1 getservbyport
		$a_01_2 = {4d 6f 7a 69 6c 6c 61 2f 33 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 49 6e 64 79 20 4c 69 62 72 61 72 79 29 } //1 Mozilla/3.0 (compatible; Indy Library)
		$a_01_3 = {50 61 73 73 77 6f 72 64 } //1 Password
		$a_01_4 = {6d 73 6f 65 40 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //1 msoe@microsoft.com
		$a_01_5 = {43 3a 5c 43 6f 6d 6d 6f 6e 66 69 6c 65 73 5c } //1 C:\Commonfiles\
		$a_01_6 = {5c 64 72 69 76 65 5f 73 79 73 74 65 6d 2e 73 79 73 } //1 \drive_system.sys
		$a_01_7 = {5c 6f 75 74 6c 6f 6b 2e 65 78 65 } //1 \outlok.exe
		$a_01_8 = {5c 65 6d 61 69 6c 73 2e 74 78 74 } //1 \emails.txt
		$a_01_9 = {32 32 2e 6d 6f 64 } //1 22.mod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=7
 
}