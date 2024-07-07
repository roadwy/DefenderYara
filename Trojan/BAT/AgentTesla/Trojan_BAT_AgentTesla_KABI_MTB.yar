
rule Trojan_BAT_AgentTesla_KABI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KABI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 11 0c 08 11 09 1f 16 5d 91 61 07 11 0b 11 04 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 11 09 17 58 13 09 11 09 11 04 09 17 58 5a 32 ba } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}