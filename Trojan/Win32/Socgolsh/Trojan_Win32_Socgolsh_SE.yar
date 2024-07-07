
rule Trojan_Win32_Socgolsh_SE{
	meta:
		description = "Trojan:Win32/Socgolsh.SE,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //1 python.exe
		$a_00_1 = {70 00 79 00 74 00 68 00 6f 00 6e 00 77 00 2e 00 65 00 78 00 65 00 } //1 pythonw.exe
		$a_00_2 = {74 00 61 00 73 00 6b 00 68 00 6f 00 73 00 74 00 77 00 2e 00 65 00 78 00 65 00 } //1 taskhostw.exe
		$a_02_3 = {2e 00 70 00 79 00 20 00 90 02 ff 20 00 2d 00 69 00 70 00 20 00 90 02 ff 20 00 2d 00 70 00 6f 00 72 00 74 00 20 00 90 00 } //100
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*100) >=101
 
}