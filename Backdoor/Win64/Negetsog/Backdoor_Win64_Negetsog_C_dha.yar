
rule Backdoor_Win64_Negetsog_C_dha{
	meta:
		description = "Backdoor:Win64/Negetsog.C!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 67 72 61 6d 20 6e 69 65 6c 73 6f 6e 20 6d 61 6e 64 65 6c 20 6d 65 61 64 6f 77 73 20 6c 6f 76 65 6c 6c } //01 00  ingram nielson mandel meadows lovell
		$a_01_1 = {64 65 65 36 63 65 39 31 34 37 33 64 61 66 66 66 } //00 00  dee6ce91473dafff
	condition:
		any of ($a_*)
 
}