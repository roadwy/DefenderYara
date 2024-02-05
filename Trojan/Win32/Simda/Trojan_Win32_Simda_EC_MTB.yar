
rule Trojan_Win32_Simda_EC_MTB{
	meta:
		description = "Trojan:Win32/Simda.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 75 6d 6f 4a 6f 73 65 } //01 00 
		$a_01_1 = {45 6e 75 6d 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 57 } //01 00 
		$a_01_2 = {47 75 6e 61 53 79 73 65 43 75 66 79 46 61 } //01 00 
		$a_01_3 = {4e 65 78 65 66 6f 71 79 } //01 00 
		$a_01_4 = {44 77 67 68 7a 66 62 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}