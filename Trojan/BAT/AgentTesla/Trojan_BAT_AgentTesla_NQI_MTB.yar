
rule Trojan_BAT_AgentTesla_NQI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 32 00 00 5d 07 09 20 00 32 00 00 5d 91 08 09 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 09 17 58 20 00 32 00 00 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5e d2 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d ad } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}