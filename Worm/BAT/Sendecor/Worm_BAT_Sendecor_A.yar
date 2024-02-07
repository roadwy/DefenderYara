
rule Worm_BAT_Sendecor_A{
	meta:
		description = "Worm:BAT/Sendecor.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 46 69 6c 65 53 65 6e 64 65 72 00 } //01 00  潌䙧汩卥湥敤r
		$a_01_1 = {74 6d 72 53 65 6e 64 4c 6f 67 00 } //01 00 
		$a_01_2 = {48 44 44 65 74 65 63 74 6f 72 00 } //01 00 
		$a_01_3 = {4e 65 74 44 65 74 65 63 74 6f 72 00 } //01 00  敎䑴瑥捥潴r
		$a_01_4 = {4d 53 75 70 64 61 74 65 2e 4d 79 00 } //00 00  卍灵慤整䴮y
	condition:
		any of ($a_*)
 
}