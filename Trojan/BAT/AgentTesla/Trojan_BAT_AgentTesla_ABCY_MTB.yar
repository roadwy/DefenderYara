
rule Trojan_BAT_AgentTesla_ABCY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 59 7e 0b 00 00 04 20 16 02 00 00 95 5f 7e 0b 00 00 04 20 dd 04 00 00 95 61 58 80 15 00 00 04 38 ae 06 00 00 7e 15 00 00 04 7e 0b 00 00 04 20 3c 02 00 00 95 33 61 7e 15 00 00 04 7e 2b 00 00 04 17 9a 1c 95 7e 0b 00 00 04 20 ac 03 00 00 95 58 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}