
rule Backdoor_BAT_Bladabindi_AH{
	meta:
		description = "Backdoor:BAT/Bladabindi.AH,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 6a 52 41 54 2e 70 72 6f 63 2e 72 65 73 6f 75 72 63 65 73 } //10 njRAT.proc.resources
		$a_01_1 = {42 75 69 6c 64 65 72 2e 72 65 73 6f 75 72 63 65 73 } //10 Builder.resources
		$a_01_2 = {6e 6a 52 41 54 2e 43 68 61 74 2e 72 65 73 6f 75 72 63 65 73 } //10 njRAT.Chat.resources
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}