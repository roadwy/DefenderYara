
rule TrojanSpy_Win32_Delf_CH{
	meta:
		description = "TrojanSpy:Win32/Delf.CH,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {5c 63 73 72 73 73 2e 65 78 65 } //02 00 
		$a_01_1 = {46 6c 79 20 46 6f 72 20 46 75 6e } //01 00 
		$a_01_2 = {54 69 6d 65 72 31 54 69 6d 65 72 } //02 00 
		$a_01_3 = {3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c } //00 00 
	condition:
		any of ($a_*)
 
}