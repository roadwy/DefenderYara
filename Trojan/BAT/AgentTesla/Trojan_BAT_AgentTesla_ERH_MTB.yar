
rule Trojan_BAT_AgentTesla_ERH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ERH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 04 20 00 c0 00 00 5d 03 02 20 00 c0 00 00 04 ?? ?? ?? ?? ?? 03 04 17 58 20 00 c0 00 00 5d 91 ?? ?? ?? ?? ?? 59 06 58 06 5d ?? ?? ?? ?? ?? 9c 03 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}