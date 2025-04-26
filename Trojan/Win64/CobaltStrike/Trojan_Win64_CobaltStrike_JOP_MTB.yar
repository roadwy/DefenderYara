
rule Trojan_Win64_CobaltStrike_JOP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 c0 49 83 e0 ?? 75 ?? 88 d3 eb ?? 88 cb 30 1c 07 48 ff c0 48 39 f0 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}