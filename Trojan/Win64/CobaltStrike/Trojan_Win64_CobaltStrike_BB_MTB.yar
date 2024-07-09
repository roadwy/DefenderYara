
rule Trojan_Win64_CobaltStrike_BB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 ?? 41 8a 14 14 32 54 05 ?? 88 14 03 48 ff c0 eb 90 0a 19 00 39 f8 7d 16 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win64_CobaltStrike_BB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 29 c3 45 01 d9 45 01 cc 4d 63 e4 42 32 0c 20 48 8b 44 24 ?? 88 0c 10 48 8b 44 24 ?? 48 39 44 24 ?? 48 8d 58 01 90 13 b8 ?? ?? ?? ?? 44 8b 0d ?? ?? ?? ?? 44 8b 05 ?? ?? ?? ?? 41 f7 ef } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}