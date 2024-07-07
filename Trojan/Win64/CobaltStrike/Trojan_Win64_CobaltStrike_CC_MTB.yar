
rule Trojan_Win64_CobaltStrike_CC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c0 48 63 f8 4c 8d 84 90 01 05 45 0f b6 0c 90 01 01 41 03 d1 81 e2 90 01 04 90 13 48 63 c2 48 8d 8c 90 01 05 48 03 c8 0f b6 01 41 88 04 90 01 01 44 88 09 41 0f b6 04 90 01 01 41 03 c1 0f b6 c0 0f b6 8c 90 01 05 41 30 0a 49 ff c2 49 83 eb 01 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win64_CobaltStrike_CC_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8b 0c 80 41 31 0c 90 01 01 8b 8e 90 01 04 23 cb 90 13 48 8b 96 90 01 04 48 63 86 90 01 04 44 8b 04 82 85 c9 90 13 48 63 86 90 01 04 45 03 ce 44 01 04 82 8b 86 90 00 } //2
		$a_03_1 = {8b 0c 81 31 0a 8b 8b 90 01 04 81 e1 90 01 04 90 13 48 8b 93 90 01 04 48 63 83 90 01 04 44 8b 04 82 85 c9 90 13 48 63 83 90 01 04 41 ff c1 44 01 04 82 0f b6 05 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}