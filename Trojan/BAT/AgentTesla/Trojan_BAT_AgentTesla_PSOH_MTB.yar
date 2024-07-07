
rule Trojan_BAT_AgentTesla_PSOH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSOH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 08 28 48 00 00 06 72 c7 03 00 70 72 cb 03 00 70 28 54 00 00 06 72 cf 03 00 70 72 d3 03 00 70 6f 60 00 00 0a 13 08 38 e4 fe ff ff 00 02 16 28 5a 00 00 06 20 00 00 00 00 28 51 00 00 06 39 90 fd ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}