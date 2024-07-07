
rule Trojan_Win64_CobaltStrike_MO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 6c 24 78 48 8d 6c 24 78 48 89 84 24 88 00 00 00 4c 89 84 24 b0 00 00 00 48 89 bc 24 a0 00 00 00 48 89 b4 24 a8 00 00 00 e8 90 01 04 0f 1f 00 48 85 c9 0f 85 04 01 00 00 90 01 01 b9 0c 00 00 00 bf 10 00 00 00 90 00 } //1
		$a_01_1 = {56 76 5a 64 78 38 6b 79 44 78 38 77 43 5a 65 57 52 62 73 4b } //1 VvZdx8kyDx8wCZeWRbsK
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_CobaltStrike_MO_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 53 6c 48 8b 05 90 01 04 45 8b c1 41 c1 e8 10 48 8b 88 c0 00 00 00 44 88 04 0a 41 8b d1 ff 43 6c 48 8b 05 90 01 04 c1 ea 08 48 63 48 6c 48 8b 80 c0 00 00 00 88 14 01 90 00 } //1
		$a_03_1 = {48 8b 0d 70 8b 01 00 83 e8 56 31 41 74 48 8b 05 90 01 04 8b 88 e0 00 00 00 b8 bd 8c 08 00 33 0d 90 01 04 2b c1 01 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}