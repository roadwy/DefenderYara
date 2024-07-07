
rule PWS_Win32_Mifeng_gen_A{
	meta:
		description = "PWS:Win32/Mifeng.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 68 64 6f 63 76 77 5f 74 6c 62 40 54 43 70 70 57 65 62 42 72 6f 77 73 65 72 } //1 Shdocvw_tlb@TCppWebBrowser
		$a_01_1 = {66 62 3a 43 2b 2b 48 4f 4f 4b } //1 fb:C++HOOK
		$a_01_2 = {77 65 62 73 61 6d 62 61 2e 63 6f 6d } //1 websamba.com
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_00_4 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Windows\CurrentVersion\Run
		$a_01_5 = {6e 65 74 20 73 74 6f 70 20 22 49 6e 74 65 72 6e 65 74 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 46 69 72 65 77 61 6c 6c } //1 net stop "Internet Connection Firewall
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_7 = {6d 75 6c 74 69 70 61 72 74 2f 61 6c 74 65 72 6e 61 74 69 76 65 } //1 multipart/alternative
		$a_03_8 = {68 74 74 70 3a 2f 2f 62 65 66 6f 72 65 2e 90 01 02 2e 73 74 90 00 } //2
		$a_01_9 = {2f 72 79 61 62 63 64 65 66 67 2f 6d 66 36 64 62 2f 69 6e 64 65 78 2e 61 73 70 3f 65 76 65 3d } //2 /ryabcdefg/mf6db/index.asp?eve=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*2+(#a_01_9  & 1)*2) >=8
 
}