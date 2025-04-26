
rule Trojan_BAT_AgentTesla_ABKX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 59 7e 32 00 00 04 20 73 03 00 00 95 5f 7e 32 00 00 04 07 0b 20 ea 00 00 00 95 61 59 80 2b 00 00 04 2b 72 7e 2b 00 00 04 7e 32 00 00 04 20 28 01 00 00 95 33 25 7e 2b 00 00 04 7e 32 00 00 04 20 cf 01 00 00 95 58 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}