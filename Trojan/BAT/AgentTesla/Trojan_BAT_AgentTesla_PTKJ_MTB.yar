
rule Trojan_BAT_AgentTesla_PTKJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 da 1f 13 14 1b 20 af 1d dd 1c 28 ?? 02 00 06 28 ?? 01 00 06 09 75 0d 00 00 1b 28 ?? 01 00 06 a2 1d 13 07 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}