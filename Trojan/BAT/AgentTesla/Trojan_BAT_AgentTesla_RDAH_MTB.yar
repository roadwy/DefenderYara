
rule Trojan_BAT_AgentTesla_RDAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 7b 07 00 00 04 6f 2b 00 00 0a 28 2c 00 00 0a 0c 16 13 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}