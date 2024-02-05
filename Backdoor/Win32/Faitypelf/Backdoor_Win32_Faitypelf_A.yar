
rule Backdoor_Win32_Faitypelf_A{
	meta:
		description = "Backdoor:Win32/Faitypelf.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 68 34 02 00 00 50 8d 94 3e 34 02 00 00 56 55 89 54 24 40 ff 15 } //01 00 
		$a_01_1 = {8b 31 80 3e 2d 0f 84 } //01 00 
		$a_01_2 = {5b 6d 73 6e 62 6f 74 5d } //00 00 
	condition:
		any of ($a_*)
 
}