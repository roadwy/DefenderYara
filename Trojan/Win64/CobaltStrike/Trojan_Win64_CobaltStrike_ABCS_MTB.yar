
rule Trojan_Win64_CobaltStrike_ABCS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ABCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 48 99 49 f7 f9 41 0f b6 04 13 41 30 04 0a 48 ff c1 48 89 0c 24 4c 39 04 24 ?? ?? 48 8b 0c 24 48 89 c8 4c 09 c8 48 c1 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_CobaltStrike_ABCS_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ABCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 ?? 4d 8d 40 01 8b c2 ff c2 83 e0 0f 0f b6 44 04 ?? 42 30 44 01 ?? 3b d3 72 e2 } //6
		$a_03_1 = {4c 8b 44 24 ?? 4d 8d 52 01 41 8b c9 b8 ?? ?? ?? ?? 41 f7 e1 41 ff c1 c1 ea 03 6b c2 0f 2b c8 0f b6 4c 0c ?? 43 30 4c 10 ff 44 3b cb } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}