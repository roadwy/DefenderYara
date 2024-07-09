
rule Trojan_Win64_CobaltStrike_MGK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 8b c1 0f a2 89 04 24 b8 [0-04] 89 4c 24 08 23 c8 89 5c 24 04 89 54 24 0c 3b c8 75 2c } //1
		$a_01_1 = {b9 10 27 00 00 ff 15 15 fb 00 00 eb f3 } //1
		$a_03_2 = {8b 44 24 08 ff c0 89 44 24 08 8b 44 24 10 8b 4c 24 08 99 f7 f9 89 44 24 10 8b 44 24 10 83 e8 [0-01] 89 44 24 10 8b 44 24 08 83 c0 [0-01] 89 44 24 08 8b 44 24 08 83 f8 [0-01] 7c c8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}