
rule Trojan_Win64_CobaltStrike_BOW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BOW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 8d 14 23 48 89 f9 30 54 18 08 e8 ?? ?? ?? ?? 48 8b 44 24 48 48 89 f2 48 89 f9 48 c1 fa 08 30 54 18 08 e8 } //5
		$a_03_1 = {48 89 f2 48 89 f9 48 c1 fa 10 48 c1 fe 18 30 54 18 08 e8 ?? ?? ?? ?? 48 8b 44 24 48 40 30 74 18 08 48 ff c3 eb } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}