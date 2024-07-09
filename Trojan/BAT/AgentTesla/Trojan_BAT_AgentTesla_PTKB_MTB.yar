
rule Trojan_BAT_AgentTesla_PTKB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 15 31 10 12 01 07 8e 69 28 ?? 00 00 2b 07 28 ?? 00 00 0a 16 2d f7 07 28 ?? 00 00 0a 0d 07 2c 3d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}