
rule Backdoor_Win32_Delf_JX{
	meta:
		description = "Backdoor:Win32/Delf.JX,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //02 00 
		$a_01_1 = {5c 77 61 75 61 63 6c 74 2e 6c 6e 6b } //01 00 
		$a_01_2 = {77 65 62 63 61 6d 66 61 69 6c } //01 00 
		$a_01_3 = {3a 4f 6e 6c 69 6e 65 3a } //01 00 
		$a_01_4 = {66 69 72 73 74 62 6d 70 } //02 00 
		$a_01_5 = {77 61 75 61 63 6c 74 2d 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}