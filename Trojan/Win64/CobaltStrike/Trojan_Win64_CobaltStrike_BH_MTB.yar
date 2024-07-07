
rule Trojan_Win64_CobaltStrike_BH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 3e 10 8a 44 05 10 88 44 3b 10 48 ff c7 eb } //1
		$a_03_1 = {49 8b 14 24 48 39 d7 72 90 01 01 48 ff ca eb 90 01 01 48 83 ca ff 48 89 f9 e8 90 02 04 8a 44 33 10 41 88 44 3c 10 48 83 c7 01 71 90 01 01 e8 90 02 04 48 83 c6 01 71 90 01 01 e8 90 02 04 48 3b 2b 74 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}