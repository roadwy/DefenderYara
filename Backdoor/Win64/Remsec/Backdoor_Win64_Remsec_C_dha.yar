
rule Backdoor_Win64_Remsec_C_dha{
	meta:
		description = "Backdoor:Win64/Remsec.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {49 6e 69 74 69 61 6c 69 7a 65 50 72 69 6e 74 50 72 6f 76 69 64 6f 72 } //0a 00 
		$a_01_1 = {8d 88 00 00 00 3a } //00 00 
	condition:
		any of ($a_*)
 
}