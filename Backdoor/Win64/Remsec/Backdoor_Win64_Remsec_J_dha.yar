
rule Backdoor_Win64_Remsec_J_dha{
	meta:
		description = "Backdoor:Win64/Remsec.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b 67 61 74 65 2e 64 6c 6c 00 69 6e 69 74 32 00 6d 61 69 6e 32 00 76 65 72 73 69 6f 6e 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}