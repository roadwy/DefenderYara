
rule TrojanProxy_Win32_Delf_I{
	meta:
		description = "TrojanProxy:Win32/Delf.I,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 56 69 65 77 65 72 } //1 Windows Update Viewer
		$a_01_1 = {5c 52 44 50 4c 69 63 65 6e 73 65 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 \RDPLicense\svchost.exe
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_3 = {46 61 73 74 4d 4d 20 42 6f 72 6c 61 6e 64 20 45 64 69 74 69 6f 6e 20 } //1 FastMM Borland Edition 
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 6f 2e 72 75 } //1 http://www.gooo.ru
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}