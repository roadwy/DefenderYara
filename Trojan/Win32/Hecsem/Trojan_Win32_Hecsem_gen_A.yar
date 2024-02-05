
rule Trojan_Win32_Hecsem_gen_A{
	meta:
		description = "Trojan:Win32/Hecsem.gen!A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_1 = {68 6f 6f 6b 2e 64 6c 6c 00 45 6a 65 63 75 74 61 62 6c 65 } //01 00 
		$a_01_2 = {48 6f 6f 6b 4f 66 66 00 48 6f 6f 6b 4f 6e } //01 00 
		$a_01_3 = {5c 53 68 65 6c 6c 5c 4f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 } //01 00 
		$a_01_4 = {00 73 6d 63 63 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}