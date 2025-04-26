
rule Trojan_Win64_CobaltStrike_ZGG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 ff c7 4c 89 f2 4d 89 f8 e8 ?? ?? ?? ?? 48 ba 00 00 00 00 ?? ?? ?? ?? 4d 89 e6 42 8d 04 2e 43 30 44 2e 08 4a 8d 2c 2e 4c 8b 77 08 49 85 16 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}