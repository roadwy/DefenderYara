
rule Trojan_BAT_AgentTesla_EHH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 06 07 91 20 ?? ?? ?? ?? 59 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}