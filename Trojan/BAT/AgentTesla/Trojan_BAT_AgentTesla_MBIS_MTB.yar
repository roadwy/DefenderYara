
rule Trojan_BAT_AgentTesla_MBIS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 72 00 69 00 6e 00 67 00 31 00 00 05 3e 00 3c 00 00 03 7e 00 00 05 7b 00 7d 00 00 05 7d 00 7d 00 00 03 7d 00 00 03 30 00 00 0f 20 00 4c 00 6f 00 2d 00 61 00 64 00 20 00 00 03 2d 00 00 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 } //10
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}