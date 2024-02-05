
rule Trojan_Win64_Isator_A_bit{
	meta:
		description = "Trojan:Win64/Isator.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 69 74 72 61 6e 73 6c 61 74 6f 72 5c 69 74 72 61 6e 73 6c 61 74 6f 72 2e 64 6c 6c } //01 00 
		$a_01_1 = {67 6c 2e 69 6d 6d 65 72 65 65 61 6b 6f 2e 69 6e 66 6f 2f 67 6c 2e 70 68 70 3f 75 69 64 3d } //01 00 
		$a_01_2 = {42 48 44 77 6f 6e 6c 6f 61 64 55 70 64 61 74 65 46 69 6c 65 } //01 00 
		$a_01_3 = {5c 2e 5c 69 54 72 61 6e 73 6c 61 74 6f 72 43 74 72 6c } //00 00 
	condition:
		any of ($a_*)
 
}