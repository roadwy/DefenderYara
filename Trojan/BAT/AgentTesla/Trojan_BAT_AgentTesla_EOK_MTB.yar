
rule Trojan_BAT_AgentTesla_EOK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 90 01 03 06 02 07 17 58 02 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a 9c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}