
rule TrojanSpy_Win32_Delf_CJ{
	meta:
		description = "TrojanSpy:Win32/Delf.CJ,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 73 6d 73 73 2e 65 78 65 } //02 00 
		$a_01_1 = {53 53 20 53 65 63 75 72 69 74 79 20 53 65 72 76 69 63 65 73 } //04 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 66 72 65 65 7a 64 65 63 2e 72 75 2f 73 65 72 76 69 63 65 75 70 64 61 74 65 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}