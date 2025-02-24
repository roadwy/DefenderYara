
rule Trojan_Win64_CobaltStrike_MP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c2 83 e2 07 8a 54 15 00 32 14 07 88 14 06 48 ff c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_MP_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 79 46 64 69 5a } //1 ByFdiZ
		$a_01_1 = {56 73 58 43 7a 63 72 } //1 VsXCzcr
		$a_01_2 = {56 4a 69 44 54 } //1 VJiDT
		$a_01_3 = {77 65 65 75 6c 73 66 37 36 33 62 73 31 2e 64 6c 6c } //1 weeulsf763bs1.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_CobaltStrike_MP_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 63 c3 49 8b c7 ff c3 49 f7 e0 48 c1 ea 04 48 8d 04 d2 48 03 c0 4c 2b c0 4d 0f af c3 42 8a 44 05 87 42 32 04 0e 41 88 01 49 ff c1 81 fb 00 ba 01 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_MP_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e8 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b d2 2c 41 8b c0 2b c2 48 63 c8 42 0f b6 94 11 d8 e8 00 00 43 32 94 11 d0 53 0a 00 48 8b 44 24 30 41 88 14 01 41 ff c0 49 ff c1 49 63 c0 48 3b 44 24 38 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}