
rule Trojan_Win64_CobaltStrike_MJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af d0 48 8b 83 c8 00 00 00 88 14 01 44 8b 83 b4 00 00 00 8b 4b 54 44 8b 8b e0 00 00 00 8b ab d8 00 00 00 8b c5 ff 83 88 00 00 00 41 8d 90 01 05 8b 73 58 41 33 c0 90 00 } //5
		$a_03_1 = {89 43 54 89 0b 8d 82 90 01 04 41 03 c1 01 43 08 44 8b 73 08 49 81 fb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_Win64_CobaltStrike_MJ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f a2 44 8b c9 c7 05 00 91 05 00 01 00 00 00 81 f1 63 41 4d 44 44 8b d2 81 f2 65 6e 74 69 8b fb 81 f7 41 75 74 68 8b f0 0b fa 44 8b c3 0b f9 41 81 f0 47 65 6e 75 33 c9 41 81 f2 69 6e 65 49 45 0b d0 b8 01 00 00 00 44 8b 05 49 b4 05 00 41 81 f1 6e 74 65 6c 45 0b d1 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}