
rule Backdoor_Win64_Remsec_D_dha{
	meta:
		description = "Backdoor:Win64/Remsec.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {b8 7a 7a 7a 7a } //0a 00 
		$a_01_1 = {b8 71 71 71 71 } //0a 00 
		$a_01_2 = {b8 79 79 79 79 } //0a 00 
		$a_01_3 = {e9 9b f5 c6 ac e9 87 a9 9b bb 87 a3 88 } //00 00 
	condition:
		any of ($a_*)
 
}