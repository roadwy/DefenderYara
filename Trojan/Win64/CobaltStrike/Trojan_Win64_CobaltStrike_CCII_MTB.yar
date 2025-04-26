
rule Trojan_Win64_CobaltStrike_CCII_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b c2 48 98 48 8b 8c 24 ?? ?? ?? ?? 0f be 04 01 48 8b 8c 24 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 0f b6 0c 11 33 c8 8b c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}