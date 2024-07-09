
rule Trojan_BAT_AgentTesla_MLQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {17 9a 0b 02 07 28 [0-05] 16 28 [0-05] 16 90 09 16 00 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0a 06 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}