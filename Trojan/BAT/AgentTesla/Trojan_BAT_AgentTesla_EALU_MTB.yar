
rule Trojan_BAT_AgentTesla_EALU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EALU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 11 06 1f 33 91 13 05 2b ba 16 0a 16 13 05 2b b3 04 05 61 1f 13 59 06 61 ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? 19 13 05 2b 99 1d 2b f9 11 06 ?? ?? ?? ?? ?? 91 1f 66 59 2b ec 02 0b 1f 09 13 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}