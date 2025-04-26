
rule Trojan_Win32_Farfli_BE_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {44 65 62 75 67 5c 45 69 64 6f 6c 6f 6e 2e 65 78 65 } //Debug\Eidolon.exe  1
		$a_80_1 = {45 69 64 6f 6c 6f 6e 52 75 6e } //EidolonRun  1
		$a_80_2 = {77 77 77 2e 78 79 39 39 39 2e 63 6f 6d } //www.xy999.com  1
		$a_80_3 = {45 69 64 6f 6c 6f 6e 44 6c 67 } //EidolonDlg  1
		$a_80_4 = {45 69 64 6f 6c 6f 6e 2e 69 6e 69 } //Eidolon.ini  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}