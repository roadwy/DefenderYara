
rule Trojan_BAT_AgentTesla_PTGB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7b 0c 00 00 04 17 8d 74 00 00 01 25 16 1f 5f 9d 6f 9c 00 00 0a 0b 06 28 ?? 00 00 06 28 ?? 00 00 0a 0c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}