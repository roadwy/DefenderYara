
rule Trojan_BAT_AgentTesla_UYLL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.UYLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 a1 ce d2 c4 28 ?? ?? ?? 06 07 08 28 ?? ?? ?? 06 0b 08 15 58 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}