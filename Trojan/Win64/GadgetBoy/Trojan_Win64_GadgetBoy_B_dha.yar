
rule Trojan_Win64_GadgetBoy_B_dha{
	meta:
		description = "Trojan:Win64/GadgetBoy.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {73 74 61 74 65 2e 64 6c 6c 00 4d 6f 6e 69 74 6f 72 00 53 65 72 76 69 63 65 4d 61 69 6e } //02 00 
		$a_01_1 = {47 6c 6f 62 61 6c 2f 2f 43 43 41 50 50 25 64 } //01 00 
		$a_01_2 = {44 6d 70 74 66 58 6a 6f 65 70 78 54 75 62 75 6a 70 6f } //01 00 
		$a_01_3 = {51 73 70 64 66 74 74 34 33 4f 66 79 75 } //00 00 
	condition:
		any of ($a_*)
 
}