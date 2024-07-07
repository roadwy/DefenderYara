
rule Trojan_BAT_AgentTesla_IQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {0b 06 07 28 90 01 03 0a 7e 90 01 03 04 6f 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 06 18 6f 90 01 03 0a 06 6f 90 01 03 0a 0c 02 0d 08 09 16 09 8e b7 6f 90 00 } //10
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {63 5f 41 6e 74 69 4b 69 6c 6c } //1 c_AntiKill
		$a_81_3 = {63 5f 49 6d 41 6e 74 69 4b 69 6c 6c } //1 c_ImAntiKill
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}