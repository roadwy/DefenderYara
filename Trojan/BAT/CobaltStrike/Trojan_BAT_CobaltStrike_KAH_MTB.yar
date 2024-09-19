
rule Trojan_BAT_CobaltStrike_KAH_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 04 2b 09 de 0d 28 ?? 00 00 06 2b f5 0a 2b f4 26 de ec 2b 01 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}