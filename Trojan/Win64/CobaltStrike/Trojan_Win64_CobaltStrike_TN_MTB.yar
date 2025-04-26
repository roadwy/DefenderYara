
rule Trojan_Win64_CobaltStrike_TN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 24 33 d2 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 44 04 ?? 48 8b 4c 24 ?? 48 8b 54 24 ?? 0f be 0c 11 33 c8 8b c1 8b 0c 24 48 8b 54 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}