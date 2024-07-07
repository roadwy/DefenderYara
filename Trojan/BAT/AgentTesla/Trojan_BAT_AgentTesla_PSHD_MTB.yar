
rule Trojan_BAT_AgentTesla_PSHD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 53 00 00 06 0a 28 37 00 00 06 0b 07 1f 20 8d 1e 00 00 01 25 d0 c7 00 00 04 28 90 01 03 0a 6f 90 01 03 0a 07 1f 10 8d 1e 00 00 01 25 d0 ca 00 00 04 28 90 01 03 0a 6f 90 01 03 0a 06 07 6f 90 01 03 0a 17 73 90 01 03 0a 25 02 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}