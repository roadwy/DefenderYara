
rule Trojan_BAT_AgentTesla_PSJF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 03 6f 89 00 00 0a 0a 02 73 ?? ?? ?? 0a 0b 07 06 16 73 ?? ?? ?? 0a 0c 00 02 8e 69 8d 4b 00 00 01 0d 08 09 16 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}