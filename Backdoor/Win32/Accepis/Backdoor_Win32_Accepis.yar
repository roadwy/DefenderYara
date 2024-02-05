
rule Backdoor_Win32_Accepis{
	meta:
		description = "Backdoor:Win32/Accepis,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {61 63 74 69 62 72 6f 77 2e 64 6c 6c 90 02 04 2f 63 90 02 04 25 73 25 73 90 00 } //01 00 
		$a_00_1 = {66 69 6c 65 3a 2f 2f 25 73 69 6e 64 65 78 2e 68 74 6d 6c } //01 00 
		$a_00_2 = {25 73 20 55 6e 69 73 74 61 6c 6c } //01 00 
		$a_00_3 = {50 48 4f 4e 45 41 43 43 45 53 53 45 58 45 } //00 00 
	condition:
		any of ($a_*)
 
}