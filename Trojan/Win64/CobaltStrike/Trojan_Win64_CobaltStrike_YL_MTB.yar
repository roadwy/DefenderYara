
rule Trojan_Win64_CobaltStrike_YL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 ea c1 fa 04 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 36 29 c1 89 c8 48 63 d0 48 8b 85 d8 02 00 00 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 e4 02 00 00 01 8b 95 e4 02 00 00 8b 85 74 02 00 00 39 c2 72 87 } //1
		$a_01_1 = {48 89 e5 48 83 ec 20 c7 45 f4 60 00 00 00 8b 45 f4 65 48 8b 00 48 89 45 e8 48 8b 45 e8 48 89 45 f8 48 8b 45 f8 48 83 c4 20 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}