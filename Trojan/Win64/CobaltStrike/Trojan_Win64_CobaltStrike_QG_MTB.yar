
rule Trojan_Win64_CobaltStrike_QG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.QG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 48 ?? 89 f2 48 89 e9 48 c1 fa ?? 30 54 18 ?? e8 ?? ?? ?? ?? 48 8b 44 24 48 ?? 89 f2 48 89 e9 48 c1 fa ?? 48 c1 fe ?? 30 54 18 ?? e8 ?? ?? ?? ?? 48 8b 44 24 ?? 40 30 74 18 ?? 48 ff c3 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}