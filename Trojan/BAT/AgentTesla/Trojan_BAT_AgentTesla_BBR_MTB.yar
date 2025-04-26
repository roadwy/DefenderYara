
rule Trojan_BAT_AgentTesla_BBR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 04 08 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 61 b7 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 07 11 05 6f ?? ?? ?? 0a 26 08 04 6f ?? ?? ?? 0a 17 da fe 01 13 06 11 06 2c 04 16 0c 2b 05 [0-02] 08 17 d6 0c 11 04 18 d6 13 04 11 04 09 31 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}