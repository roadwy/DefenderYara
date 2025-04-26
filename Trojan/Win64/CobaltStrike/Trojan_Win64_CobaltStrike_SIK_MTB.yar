
rule Trojan_Win64_CobaltStrike_SIK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 89 06 8b 44 24 50 48 8b bc 24 d0 00 00 00 48 8b b4 24 ?? ?? ?? ?? 83 e0 07 8a 04 07 42 30 04 0e 48 8b 05 ?? ?? ?? ?? 83 38 00 0f 84 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}