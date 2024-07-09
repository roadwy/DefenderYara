
rule Trojan_BAT_AgentTesla_ENY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 b4 00 00 5d 07 09 20 00 b4 00 00 5d 91 08 09 1f 16 5d ?? ?? ?? ?? ?? 61 07 09 17 58 20 00 b4 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}