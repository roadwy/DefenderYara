
rule Trojan_Win64_CobaltStrike_BF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 8a 4c 04 ?? 8b 74 24 ?? 44 89 c9 44 30 c1 40 20 f1 44 30 c6 44 20 ce 40 08 ce 40 88 74 04 ?? 49 ff c2 48 ff c0 48 83 f8 ?? 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win64_CobaltStrike_BF_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f af 43 5c 48 8b 83 b0 00 00 00 41 8b d0 c1 ea 08 88 14 01 ff 43 60 48 63 4b 60 48 8b 83 b0 00 00 00 44 88 04 01 ff 43 60 8b 43 20 8b 4b 3c 83 c0 a6 03 c8 8b 83 98 00 00 00 31 4b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}