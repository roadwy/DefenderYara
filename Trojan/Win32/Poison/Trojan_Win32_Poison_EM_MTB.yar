
rule Trojan_Win32_Poison_EM_MTB{
	meta:
		description = "Trojan:Win32/Poison.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 5a 45 4c 5c 6e 65 77 73 6c 65 74 74 65 72 5c 56 42 36 } //01 00 
		$a_01_1 = {48 69 63 63 75 70 70 32 } //01 00 
		$a_01_2 = {66 72 75 6d 70 36 } //01 00 
		$a_01_3 = {6e 00 73 00 6c 00 74 00 2e 00 70 00 64 00 66 00 } //01 00 
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}