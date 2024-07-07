
rule Trojan_BAT_AgentTesla_ABDJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 59 7e 21 00 00 04 16 9a 20 99 00 00 00 95 5f 7e 21 00 00 04 16 9a 20 af 04 00 00 95 61 59 81 05 00 00 01 7e 21 00 00 04 19 9a 1f 47 95 7e 21 00 00 04 16 9a 20 ce 01 00 00 95 33 7a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}