
rule Backdoor_Win32_UDIS{
	meta:
		description = "Backdoor:Win32/UDIS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 44 49 53 2d 48 54 4d 4c 20 2d 20 4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //01 00 
		$a_01_1 = {52 75 6e 44 6c 6c 33 32 20 55 44 43 6f 6e 6e 2e 64 6c 6c 2c 52 75 6e 41 73 49 63 6f 6e 20 25 73 } //01 00 
		$a_01_2 = {55 44 43 6f 6e 6e 65 63 74 20 49 6e 74 65 72 66 61 63 65 } //01 00 
		$a_01_3 = {55 44 43 6f 6e 6e 2e 55 44 43 6f 6e 6e 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_UDIS_2{
	meta:
		description = "Backdoor:Win32/UDIS,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 75 6e 44 6c 6c 33 32 20 55 44 43 6f 6e 6e 2e 64 6c 6c 2c 52 75 6e 41 73 49 63 6f 6e 20 } //01 00 
		$a_01_1 = {54 72 69 61 63 6f 6d 55 44 2e 44 4c 4c 00 } //0a 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 43 68 65 63 6b 44 69 61 6c 65 72 } //0a 00 
		$a_01_3 = {44 65 49 6e 73 74 61 6c 6c 61 74 69 6f 6e } //0a 00 
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}