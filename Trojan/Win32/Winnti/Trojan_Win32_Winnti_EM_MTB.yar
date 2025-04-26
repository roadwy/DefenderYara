
rule Trojan_Win32_Winnti_EM_MTB{
	meta:
		description = "Trojan:Win32/Winnti.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {8a 5c 0c 40 32 da 88 5c 0c 40 41 3b c8 7c f1 } //1
		$a_01_1 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //1 gethostbyname
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_3 = {6d 69 63 72 6f 73 6f 66 74 2e 6e 73 30 32 2e 75 73 } //1 microsoft.ns02.us
		$a_01_4 = {77 69 6e 73 2e 6b 6f 7a 6f 77 2e 63 6f 6d } //1 wins.kozow.com
		$a_01_5 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_01_6 = {54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 5c 57 64 73 5c 72 64 70 77 64 5c 54 64 73 5c 74 63 70 } //1 Terminal Server\Wds\rdpwd\Tds\tcp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}