
rule Backdoor_Win32_Farfli_R{
	meta:
		description = "Backdoor:Win32/Farfli.R,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 00 3a 00 5c 00 4e 00 65 00 74 00 2d 00 54 00 65 00 6d 00 70 00 2e 00 69 00 6e 00 69 00 } //01 00 
		$a_00_1 = {25 73 77 69 6e 64 6f 77 73 5c 78 69 6e 73 74 61 6c 6c 25 64 2e 64 6c 6c } //0a 00 
		$a_00_2 = {63 3a 5c 57 69 6e 5f 6c 6a 2e 69 6e 69 } //0a 00 
		$a_01_3 = {43 6f 6e 6e 65 43 74 49 4f 6e 73 5c 70 62 6b 5c 72 61 53 50 48 4f 4e 45 2e 70 62 6b } //00 00 
	condition:
		any of ($a_*)
 
}