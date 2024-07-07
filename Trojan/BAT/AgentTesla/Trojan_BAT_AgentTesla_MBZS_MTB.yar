
rule Trojan_BAT_AgentTesla_MBZS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 8e 69 5d 91 61 d2 07 90 02 05 17 58 09 5d 91 59 20 00 01 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}