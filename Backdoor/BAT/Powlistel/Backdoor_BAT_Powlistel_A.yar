
rule Backdoor_BAT_Powlistel_A{
	meta:
		description = "Backdoor:BAT/Powlistel.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c5 9e 69 66 72 65 20 4c 69 73 74 65 6c 65 6d 65 } //01 00 
		$a_01_1 = {42 6c 61 63 6b 20 50 6f 77 65 72 20 53 6f 75 72 63 65 6c 65 72 } //01 00 
		$a_01_2 = {69 00 66 00 72 00 65 00 6c 00 65 00 72 00 69 00 20 00 4b 00 61 00 79 00 64 00 65 00 74 00 } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}