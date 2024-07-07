
rule Trojan_BAT_AgentTesla_NVC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 07 03 6f 90 01 03 06 28 90 01 03 0a 28 90 01 03 0a 6f 90 01 03 06 00 09 03 6f 90 01 03 06 03 6f 90 01 03 06 28 90 01 03 0a 28 90 01 03 0a 07 28 90 01 03 0a 6f 90 01 03 06 00 09 02 28 90 01 03 06 28 90 01 03 0a 6f 90 01 03 06 00 09 02 28 90 01 03 06 6f 90 01 03 06 00 09 13 08 2b 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}