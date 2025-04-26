
rule Trojan_Win64_CobaltStrike_PL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 0f 45 d1 48 8b 4d ?? 8a 44 15 ?? 30 04 0f 48 8d 4a ?? 41 ff c0 48 ff c7 49 63 c0 49 3b c1 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}