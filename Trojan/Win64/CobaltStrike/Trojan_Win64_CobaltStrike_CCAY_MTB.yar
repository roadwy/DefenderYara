
rule Trojan_Win64_CobaltStrike_CCAY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 48 6b d1 ?? 48 01 d0 48 83 f1 ?? 48 6b c9 ?? 48 01 c8 48 b9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}