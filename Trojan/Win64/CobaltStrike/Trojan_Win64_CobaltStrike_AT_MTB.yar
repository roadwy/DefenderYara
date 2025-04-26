
rule Trojan_Win64_CobaltStrike_AT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c0 80 84 04 ?? ?? ?? ?? ?? 48 ff c0 48 83 f8 ?? 75 90 0a 20 00 c6 84 24 } //1
		$a_03_1 = {44 30 c3 44 20 cb 44 20 d6 40 08 de 40 30 d6 40 88 74 04 ?? 49 ff c3 48 ff c0 48 83 f8 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}