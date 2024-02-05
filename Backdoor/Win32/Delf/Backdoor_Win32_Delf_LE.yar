
rule Backdoor_Win32_Delf_LE{
	meta:
		description = "Backdoor:Win32/Delf.LE,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {7b 36 41 44 45 39 35 39 36 2d 39 46 42 34 2d 34 32 36 41 2d 41 43 36 42 2d 44 41 45 35 42 41 39 35 43 34 39 41 7d } //04 00 
		$a_01_1 = {50 6c 75 73 43 6d 64 43 6f 6e 73 74 55 6e 69 74 } //02 00 
		$a_01_2 = {55 72 6c 4a 75 64 67 65 } //00 00 
	condition:
		any of ($a_*)
 
}