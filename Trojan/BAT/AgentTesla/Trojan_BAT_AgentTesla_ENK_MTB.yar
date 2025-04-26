
rule Trojan_BAT_AgentTesla_ENK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 20 00 38 01 00 5d 06 08 20 00 38 01 00 5d 91 07 08 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 06 08 17 58 20 00 38 01 00 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a 9c 08 15 58 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}