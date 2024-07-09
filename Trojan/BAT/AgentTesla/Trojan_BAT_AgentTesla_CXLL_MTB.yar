
rule Trojan_BAT_AgentTesla_CXLL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CXLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 17 5f 2d 20 11 1c 20 ?? ?? ?? ?? 06 61 07 58 5a 06 20 ?? ?? ?? ?? 58 07 61 58 13 1c 11 1c 1f 10 64 d1 13 16 11 16 d2 13 2b 11 16 1e 63 d1 13 16 11 18 11 0a 91 13 24 11 18 11 0a 11 28 11 24 61 19 11 20 58 61 11 2b 61 d2 9c 11 0a 17 58 13 0a 11 24 13 20 11 0a 11 27 32 a4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}