
rule Trojan_Win64_CobaltStrike_CI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 03 03 c3 0f b6 c0 0f b6 8c 04 90 01 02 00 00 80 c1 03 41 30 0a 49 ff c2 48 83 ef 01 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_CobaltStrike_CI_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 8b cb ff c3 d1 fa 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 63 c1 42 0f b6 04 10 41 30 40 90 01 01 49 83 e9 90 01 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}