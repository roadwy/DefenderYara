
rule Backdoor_Win64_Remsec_I_dha{
	meta:
		description = "Backdoor:Win64/Remsec.I!dha,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 c4 e4 e8 90 01 01 00 00 00 eb 90 00 } //0a 00 
		$a_03_1 = {d9 34 24 e8 90 01 02 00 00 c3 90 00 } //0a 00 
		$a_03_2 = {83 c4 04 89 e5 e8 90 01 01 00 00 00 e9 90 00 } //0a 00 
		$a_03_3 = {83 c4 04 60 e8 90 01 01 00 00 00 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}