
rule Trojan_Win32_DelfInject_C_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {54 5f 5f 32 36 37 39 30 39 39 39 35 37 } //03 00 
		$a_81_1 = {57 41 5f 56 4d 53 49 42 } //03 00 
		$a_81_2 = {54 5f 5f 32 36 37 30 36 35 31 36 33 31 } //03 00 
		$a_81_3 = {38 4e 4c 4c 37 4f 4d 4d 37 50 4e 4e 36 38 37 36 30 } //03 00 
		$a_81_4 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //03 00 
		$a_81_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //03 00 
		$a_81_6 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}