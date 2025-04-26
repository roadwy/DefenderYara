
rule Trojan_BAT_AgentTesla_PSGB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 a9 01 00 06 0a 06 6f ?? ?? ?? 0a 0b 20 ed 13 04 4c 28 6f 02 00 06 28 0c 00 00 06 28 0a 00 00 06 07 73 ?? ?? ?? 0a 18 28 17 02 00 06 06 6f ?? ?? ?? 0a de 03 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}