
rule Trojan_BAT_AgentTesla_ASB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 03 08 03 6f ?? ?? ?? 0a 5d 17 d6 28 ?? ?? ?? 0a da 0d 06 09 28 ?? ?? ?? 0a 13 04 12 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0a [0-01] 08 17 d6 0c 08 07 fe 02 16 fe 01 13 05 11 05 2d } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}