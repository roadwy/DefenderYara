
rule Trojan_Win32_Socgolsh_SE{
	meta:
		description = "Trojan:Win32/Socgolsh.SE,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00  python.exe
		$a_00_1 = {70 00 79 00 74 00 68 00 6f 00 6e 00 77 00 2e 00 65 00 78 00 65 00 } //01 00  pythonw.exe
		$a_00_2 = {74 00 61 00 73 00 6b 00 68 00 6f 00 73 00 74 00 77 00 2e 00 65 00 78 00 65 00 } //64 00  taskhostw.exe
		$a_02_3 = {2e 00 70 00 79 00 20 00 90 02 ff 20 00 2d 00 69 00 70 00 20 00 90 02 ff 20 00 2d 00 70 00 6f 00 72 00 74 00 20 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}