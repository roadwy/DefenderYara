
rule Trojan_BAT_AgentTesla_NNLL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NNLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 6f 7e 02 ?? ?? 08 07 5d 91 0d 0e 04 08 0e 05 58 03 08 04 58 91 02 6f 7d 02 ?? ?? 09 06 5d 91 61 d2 9c 08 17 58 0c 08 05 32 d5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}