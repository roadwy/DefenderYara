
rule Backdoor_Win32_Grifwin_A{
	meta:
		description = "Backdoor:Win32/Grifwin.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 25 73 5c 25 73 2e 65 78 65 00 00 57 69 6e 67 72 66 6d 4d 75 74 65 78 00 } //01 00 
		$a_01_1 = {49 44 52 5f 41 47 45 4e 54 49 44 00 } //01 00 
		$a_01_2 = {4c 6f 77 4c 65 76 65 6c 4d 6f 75 73 65 50 72 6f 63 00 00 00 4c 6f 77 4c 65 76 65 6c 4b 65 79 62 6f 61 72 64 50 72 6f 63 00 } //00 00 
	condition:
		any of ($a_*)
 
}