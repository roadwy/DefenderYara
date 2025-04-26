
rule Trojan_Win64_CobaltStrike_KEP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb 41 8b d8 0f b6 14 01 41 8b c1 02 14 39 c1 e0 04 41 33 c1 41 88 14 38 44 3b 05 ?? ?? ?? ?? 89 05 ?? 2e 00 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}