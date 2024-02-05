
rule Backdoor_Win32_Tupty_A{
	meta:
		description = "Backdoor:Win32/Tupty.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 65 6c 43 6f 6d 65 20 54 6f 20 54 70 6f 72 74 } //01 00 
		$a_00_1 = {45 78 65 63 75 74 65 20 54 68 65 20 43 6f 6d 6d 61 6e 64 20 77 69 74 68 20 4c 6f 6e 67 6f 6e 20 55 73 65 72 20 46 61 69 6c 65 64 } //01 00 
		$a_02_2 = {49 6e 73 74 61 6c 6c 54 65 72 6d 20 50 6f 72 74 20 90 02 20 2d 2d 3e 49 6e 73 74 61 6c 6c 20 4e 65 77 20 54 65 72 6d 69 6e 61 6c 20 50 6f 72 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}