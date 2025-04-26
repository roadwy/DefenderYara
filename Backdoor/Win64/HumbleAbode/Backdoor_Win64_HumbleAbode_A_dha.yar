
rule Backdoor_Win64_HumbleAbode_A_dha{
	meta:
		description = "Backdoor:Win64/HumbleAbode.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 00 61 00 67 00 65 00 6e 00 74 00 45 00 72 00 72 00 6f 00 72 00 2f 00 25 00 73 00 2f 00 25 00 69 00 } //1 /agentError/%s/%i
		$a_01_1 = {2f 00 65 00 6e 00 64 00 54 00 61 00 73 00 6b 00 2f 00 25 00 73 00 } //1 /endTask/%s
		$a_01_2 = {2f 00 61 00 73 00 6b 00 46 00 6f 00 72 00 43 00 6f 00 6d 00 65 00 2f 00 25 00 73 00 } //1 /askForCome/%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}