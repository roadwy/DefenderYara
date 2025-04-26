
rule Trojan_Win64_CobaltStrike_DY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 1f 30 03 48 ff c3 48 83 e9 01 75 ?? 48 83 ef ?? 0f 29 84 24 ?? ?? ?? ?? 48 83 ee 01 75 } //1
		$a_03_1 = {41 0f b6 84 38 ?? ?? ?? ?? 41 30 00 49 ff c0 48 83 e9 01 75 ?? 49 83 e9 01 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win64_CobaltStrike_DY_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 ca 03 c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b c1 2b 05 ?? ?? ?? ?? 48 63 c8 48 8b 84 24 ?? ?? ?? ?? 0f b6 0c 08 48 8b 84 24 ?? ?? ?? ?? 42 0f b6 04 00 33 c1 89 44 24 14 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 89 44 24 18 8b 05 ?? ?? ?? ?? 0f af 05 } //1
		$a_81_1 = {4f 23 33 37 48 57 5e 24 4c 28 6e 2b 47 77 56 65 47 28 6d 48 66 4d 75 21 28 59 51 35 79 29 6e 36 79 42 28 45 6a 5f 6e 61 48 41 55 64 3e } //1 O#37HW^$L(n+GwVeG(mHfMu!(YQ5y)n6yB(Ej_naHAUd>
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}