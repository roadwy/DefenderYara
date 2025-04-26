
rule Trojan_Win64_CobaltStrike_KI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 8b c1 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 49 f7 e1 48 c1 ea ?? 48 6b c2 ?? 4c 2b c0 43 8a 04 10 41 30 04 09 49 ff c1 4d 3b cb 76 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}