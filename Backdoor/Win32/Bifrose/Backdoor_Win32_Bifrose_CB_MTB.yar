
rule Backdoor_Win32_Bifrose_CB_MTB{
	meta:
		description = "Backdoor:Win32/Bifrose.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 74 65 6d 70 5c 76 69 72 75 73 2e 65 78 65 } //01 00 
		$a_01_1 = {74 65 6d 70 32 2e 65 78 65 } //01 00 
		$a_01_2 = {74 65 6d 70 31 2e 64 6f 63 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}