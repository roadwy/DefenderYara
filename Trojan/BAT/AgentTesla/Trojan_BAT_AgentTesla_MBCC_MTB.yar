
rule Trojan_BAT_AgentTesla_MBCC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 08 8c ?? 00 00 01 a2 14 28 ?? 01 00 0a 28 ?? 00 00 0a 0d 07 09 28 ?? 01 00 0a 1f 10 28 ?? 01 00 0a b4 6f ?? 01 00 0a 08 17 d6 0c 08 20 00 7c 00 00 32 c4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}