
rule Backdoor_Win32_Rithreto_A{
	meta:
		description = "Backdoor:Win32/Rithreto.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 69 74 63 6f 69 6e 20 62 6f 74 6e 65 74 } //01 00 
		$a_01_1 = {42 69 74 63 6f 69 6e 20 4d 69 6e 65 72 20 42 75 69 6c 64 65 72 } //01 00 
		$a_01_2 = {75 70 78 2e 65 78 65 20 2d 39 20 6d 69 6e 65 72 2e 65 78 65 } //01 00 
		$a_01_3 = {77 6f 72 6b 65 72 5f 70 61 73 73 } //01 00 
		$a_01_4 = {77 6f 72 6b 65 72 5f 6e 61 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}