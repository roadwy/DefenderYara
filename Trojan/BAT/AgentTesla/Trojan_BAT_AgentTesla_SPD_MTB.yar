
rule Trojan_BAT_AgentTesla_SPD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 09 8f 59 00 00 01 72 fd 01 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 09 17 58 0d 09 07 8e 69 32 de } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}