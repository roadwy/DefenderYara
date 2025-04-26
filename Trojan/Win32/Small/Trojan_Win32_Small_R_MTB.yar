
rule Trojan_Win32_Small_R_MTB{
	meta:
		description = "Trojan:Win32/Small.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 54 65 6d 70 44 69 72 5c 6d 77 2e 65 78 65 } //1 c:\TempDir\mw.exe
		$a_01_1 = {63 3a 5c 54 65 6d 70 44 69 72 5c 65 2e 6a 70 67 } //1 c:\TempDir\e.jpg
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 61 73 73 6f 6e 6e 65 2e 64 65 } //1 http://www.massonne.de
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}