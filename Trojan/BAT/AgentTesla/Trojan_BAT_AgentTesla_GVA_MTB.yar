
rule Trojan_BAT_AgentTesla_GVA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 d0 07 00 00 02 28 12 00 00 0a 6f 13 00 00 0a 73 14 00 00 0a 80 01 00 00 04 } //2
		$a_01_1 = {28 09 00 00 0a 02 6f 0a 00 00 0a 0a dd 07 00 00 00 26 73 0b 00 00 0a 7a 06 2a } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}