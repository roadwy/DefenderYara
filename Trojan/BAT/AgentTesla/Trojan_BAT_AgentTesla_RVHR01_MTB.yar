
rule Trojan_BAT_AgentTesla_RVHR01_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RVHR01!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_81_0 = {11 0a 11 0e 59 20 00 02 00 00 58 20 00 01 00 00 5d 20 00 04 00 00 58 20 00 02 00 00 5d 20 00 01 00 00 59 20 00 04 00 00 58 20 ff 00 00 00 5f 20 ff 00 00 00 5f } //1
	condition:
		((#a_81_0  & 1)*1) >=1
 
}