
rule Trojan_Win64_CobaltStrike_CG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c3 40 2a c7 24 10 32 03 40 32 c6 88 03 48 03 d9 49 3b dd 72 90 01 01 8b 44 24 90 01 01 49 ff c4 49 ff c6 49 ff cf 0f 85 90 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}
rule Trojan_Win64_CobaltStrike_CG_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c0 48 c1 e0 90 01 01 48 01 45 90 01 01 81 7d 90 01 05 75 90 01 01 48 8b 45 90 01 01 8b 00 89 c2 48 8b 45 90 01 01 48 01 d0 48 90 01 03 0f b7 45 90 01 01 83 e8 90 01 01 66 89 45 90 01 01 48 90 01 04 48 90 01 04 66 90 01 04 0f 85 90 00 } //1
		$a_03_1 = {48 89 c1 48 8b 45 90 01 01 48 8d 50 90 01 01 48 89 55 90 01 01 48 89 c2 0f b6 01 88 02 48 8b 45 90 01 01 48 8d 50 90 01 01 48 89 55 90 01 01 48 85 c0 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}