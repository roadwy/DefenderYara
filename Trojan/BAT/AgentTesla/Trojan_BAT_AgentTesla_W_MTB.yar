
rule Trojan_BAT_AgentTesla_W_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 0a 19 8d 90 01 03 01 25 16 7e 90 01 03 04 a2 25 17 28 90 01 03 06 a2 25 18 72 90 01 04 a2 0a 06 73 90 01 03 06 0b 2b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}