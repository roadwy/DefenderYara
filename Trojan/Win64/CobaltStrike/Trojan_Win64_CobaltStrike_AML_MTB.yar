
rule Trojan_Win64_CobaltStrike_AML_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {47 88 54 01 ff 48 ff c6 4c 89 d8 4c 89 e2 48 39 f3 0f 8e ?? 00 00 00 44 0f b6 14 06 48 85 c9 0f 84 ?? 00 00 00 49 89 c3 48 89 f0 49 89 d4 48 99 48 f7 f9 0f 1f 44 00 00 48 39 ca 0f 83 ?? 00 00 00 49 ff c1 42 0f b6 14 22 41 31 d2 4c 39 cf 73 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}