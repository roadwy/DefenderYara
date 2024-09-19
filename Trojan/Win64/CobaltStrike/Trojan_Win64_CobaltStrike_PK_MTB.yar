
rule Trojan_Win64_CobaltStrike_PK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 63 c0 46 8a 04 02 41 b9 ?? ?? ?? ?? 31 d2 41 f7 f1 8b 44 24 ?? 41 89 d1 48 8b 54 24 ?? 4d 63 c9 46 32 04 0a 48 63 d0 44 88 04 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}