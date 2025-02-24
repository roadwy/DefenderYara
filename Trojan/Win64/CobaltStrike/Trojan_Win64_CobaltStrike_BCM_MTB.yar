
rule Trojan_Win64_CobaltStrike_BCM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b c0 48 f7 35 ?? ?? ?? ?? 0f b6 04 0a 43 30 04 01 49 ff c0 48 8b 8d ?? ?? ?? ?? 48 8b c1 4c 8b 8d ?? ?? ?? ?? 49 2b c1 4c 3b c0 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}