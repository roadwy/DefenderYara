
rule Trojan_Win32_Farfli_CBF_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 66 77 75 2e 33 33 32 32 2e 6f 72 67 } //1 sfwu.3322.org
		$a_01_1 = {63 3a 5c 57 69 6e 64 6f 77 73 5c 25 73 25 64 2e 65 78 65 } //1 c:\Windows\%s%d.exe
		$a_01_2 = {63 3a 5c 57 69 6e 64 6f 77 73 5c 42 4a 2e 65 78 65 } //1 c:\Windows\BJ.exe
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_4 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}