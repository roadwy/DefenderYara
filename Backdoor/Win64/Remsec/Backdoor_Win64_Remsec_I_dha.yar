
rule Backdoor_Win64_Remsec_I_dha{
	meta:
		description = "Backdoor:Win64/Remsec.I!dha,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c4 e4 e8 ?? 00 00 00 eb } //10
		$a_03_1 = {d9 34 24 e8 ?? ?? 00 00 c3 } //10
		$a_03_2 = {83 c4 04 89 e5 e8 ?? 00 00 00 e9 } //10
		$a_03_3 = {83 c4 04 60 e8 ?? 00 00 00 e9 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*10) >=40
 
}