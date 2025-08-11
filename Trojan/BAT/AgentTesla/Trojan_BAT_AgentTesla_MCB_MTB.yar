
rule Trojan_BAT_AgentTesla_MCB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 00 00 09 49 00 64 00 6c 00 65 00 00 0f 43 00 68 00 61 00 73 00 69 00 6e 00 67 00 00 13 53 00 65 00 61 00 72 00 63 00 68 00 69 00 6e 00 67 00 00 0d 48 00 69 00 64 00 69 00 6e 00 67 00 00 0d 49 00 6e 00 76 00 6f 00 6b } //3
		$a_01_1 = {4c 00 69 00 7a 00 61 00 72 00 64 00 53 00 6b 00 69 00 6e 00 45 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}