
rule Trojan_BAT_AgentTesla_BR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 6f dc 00 00 0a 00 00 07 6f dd 00 00 0a 0d 00 73 de 00 00 0a 13 04 00 11 04 09 17 73 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}