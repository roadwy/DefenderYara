
rule Trojan_Win64_CobaltStrike_ZB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 30 14 08 48 8b ca 48 8b c2 48 c1 e9 38 48 83 c9 01 48 c1 e0 08 48 8b d1 49 ff c0 48 33 d0 49 83 f8 ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win64_CobaltStrike_ZB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 98 33 d2 b9 3e 00 00 00 48 f7 f1 48 8b c2 89 44 24 24 48 63 44 24 24 } //1
		$a_01_1 = {8b 44 24 28 ff c0 89 44 24 28 48 8b 44 24 30 8b 00 48 8b 4c 24 30 48 03 c8 48 8b c1 48 89 44 24 30 48 8b 44 24 30 83 38 00 75 99 41 b8 00 80 00 00 33 d2 48 8b 4c 24 30 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}