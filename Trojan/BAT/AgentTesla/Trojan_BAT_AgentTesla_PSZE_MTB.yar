
rule Trojan_BAT_AgentTesla_PSZE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 25 00 00 0a 28 ?? 00 00 0a a5 01 00 00 1b 0b 11 07 20 18 0d 6a c6 5a 20 c0 a2 17 f4 61 38 df fe ff ff 17 8d 01 00 00 1b 0d 7e 01 00 00 04 02 09 16 fe 1c 01 00 00 1b 28 ?? 00 00 0a 11 07 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}