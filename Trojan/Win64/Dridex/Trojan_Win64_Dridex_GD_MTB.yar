
rule Trojan_Win64_Dridex_GD_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_02_0 = {89 c1 8a 54 24 ?? 4c 8b 44 24 ?? 48 2b 4c 24 ?? 4c 8b 4c 24 ?? 43 88 14 01 c7 84 24 [0-08] 4c 8b 44 24 ?? 48 03 4c 24 ?? 8a 54 24 17 80 c2 ?? 88 94 24 [0-04] 8b 04 24 89 84 24 [0-04] 48 89 4c 24 ?? 4c 39 c1 75 } //10
		$a_02_1 = {44 88 84 24 [0-04] 48 8b 54 24 ?? 4c 8b 54 24 ?? 4c 89 94 24 [0-04] 4c 8b 5c 24 ?? 44 8a 04 08 48 8b 44 24 ?? 42 8a 1c 18 8b 34 24 81 f6 [0-04] 89 b4 24 [0-04] 44 28 c3 88 5c 24 ?? 49 39 d1 0f 82 } //10
		$a_80_2 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  1
		$a_80_3 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=22
 
}