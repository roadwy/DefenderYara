
rule Trojan_Win64_CobaltStrike_MWQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 03 c1 41 81 e0 ?? ?? ?? ?? 7d ?? 41 ff c8 41 81 c8 ?? ?? ?? ?? 41 ff c0 49 63 c0 49 ff c3 0f b6 0c 04 42 32 4c 1f ?? 48 ff cb 41 88 4b ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}