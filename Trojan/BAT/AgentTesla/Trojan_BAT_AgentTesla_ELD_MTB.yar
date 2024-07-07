
rule Trojan_BAT_AgentTesla_ELD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ELD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 02 09 91 03 09 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 28 90 01 03 0a 61 9c 09 17 d6 0d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}