
rule Trojan_BAT_CobaltStrike_SPVX_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.SPVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 04 6f ?? ?? ?? 0a 00 06 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 28 00 00 0a 0c 00 08 07 17 73 29 00 00 0a 0d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}