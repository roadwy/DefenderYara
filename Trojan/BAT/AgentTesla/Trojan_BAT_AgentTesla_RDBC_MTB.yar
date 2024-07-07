
rule Trojan_BAT_AgentTesla_RDBC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 1f 16 5d 91 61 07 08 17 58 11 08 5d 91 59 20 00 01 00 00 58 13 09 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}