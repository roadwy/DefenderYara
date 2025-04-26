
rule Trojan_Win64_CobaltStrike_D_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 89 c9 89 c8 41 f7 ea c1 fa 04 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 06 8d 14 50 41 29 d1 4d 63 c9 48 8b 05 ?? ?? ?? ?? 42 0f b6 04 08 32 44 0c 60 41 88 04 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_D_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.D!MTB,SIGNATURE_TYPE_PEHSTR,17 00 17 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 4c 24 08 48 83 ec 68 65 48 8b 04 25 60 00 00 00 48 89 44 24 08 48 8b 44 24 08 48 8b 40 18 48 89 44 24 08 48 8b 44 24 08 48 8b 40 20 48 89 44 24 28 48 } //10
		$a_01_1 = {48 8b 44 24 50 48 63 40 3c 48 8b 4c 24 50 48 03 c8 48 8b c1 48 89 44 24 38 48 8b 44 24 38 0f b7 40 16 25 00 80 00 00 3d 00 80 00 00 75 0a c7 44 24 48 40 } //10
		$a_01_2 = {4d 5a 41 52 55 48 89 e5 48 81 ec 20 } //3
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*3) >=23
 
}