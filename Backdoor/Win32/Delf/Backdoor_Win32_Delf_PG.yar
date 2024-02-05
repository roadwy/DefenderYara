
rule Backdoor_Win32_Delf_PG{
	meta:
		description = "Backdoor:Win32/Delf.PG,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 64 73 65 74 2e 69 6e 69 } //01 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 62 6f 6f 74 2e 69 6e 69 } //01 00 
		$a_01_2 = {53 59 53 5f 49 4e 46 4f } //01 00 
		$a_01_3 = {45 47 5f 45 58 50 41 4e 44 } //01 00 
		$a_01_4 = {55 73 65 72 49 6e 69 74 4d 70 72 4c 6f 67 6f 6e 53 63 72 69 70 74 } //01 00 
		$a_01_5 = {48 4b 43 55 5c 45 6e 76 69 72 6f 6e 6d 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}