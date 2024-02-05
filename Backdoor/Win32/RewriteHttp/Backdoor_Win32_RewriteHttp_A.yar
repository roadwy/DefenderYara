
rule Backdoor_Win32_RewriteHttp_A{
	meta:
		description = "Backdoor:Win32/RewriteHttp.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 4d 44 7c } //01 00 
		$a_81_1 = {57 52 46 7c } //01 00 
		$a_81_2 = {50 49 4e 7c } //01 00 
		$a_81_3 = {49 4e 4a 7c } //01 00 
		$a_81_4 = {44 4d 50 7c } //01 00 
		$a_81_5 = {51 75 65 72 79 3d } //01 00 
		$a_81_6 = {45 42 3a 25 64 21 } //00 00 
	condition:
		any of ($a_*)
 
}