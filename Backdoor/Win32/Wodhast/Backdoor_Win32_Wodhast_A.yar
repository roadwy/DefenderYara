
rule Backdoor_Win32_Wodhast_A{
	meta:
		description = "Backdoor:Win32/Wodhast.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 4c 5f 53 54 41 52 54 55 50 } //01 00 
		$a_01_1 = {54 5f 50 52 4f 50 } //01 00 
		$a_01_2 = {5b 57 5d 20 4d 75 74 65 78 } //01 00 
		$a_01_3 = {63 6d 64 5f 69 64 } //01 00 
		$a_00_4 = {73 63 72 65 65 6e 73 68 6f 74 } //00 00 
		$a_00_5 = {5d 04 00 } //00 48 
	condition:
		any of ($a_*)
 
}