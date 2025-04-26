
rule Trojan_BAT_AgentTesla_MBXT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 00 75 00 68 00 64 00 77 00 68 00 4c 00 71 00 76 00 77 00 64 00 71 00 66 00 68 00 } //5 FuhdwhLqvwdqfh
		$a_01_1 = {54 72 69 66 33 32 } //4 Trif32
		$a_01_2 = {47 65 74 54 79 70 65 } //3 GetType
		$a_01_3 = {53 70 6c 69 74 } //2 Split
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=15
 
}