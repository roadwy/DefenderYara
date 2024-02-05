
rule Trojan_Win32_Eggnog_EM_MTB{
	meta:
		description = "Trojan:Win32/Eggnog.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 58 6f 6c 6f 78 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4c 69 6d 65 57 69 72 65 } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 6f 72 70 68 65 75 73 } //01 00 
		$a_01_3 = {43 3a 5c 4d 79 20 44 6f 77 6e 6c 6f 61 64 73 } //01 00 
		$a_01_4 = {57 6f 72 6d 2e 50 32 50 2e 47 6f 6f 67 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}