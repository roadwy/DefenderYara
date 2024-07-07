
rule Trojan_Win64_Dridex_AS_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 47 54 37 74 2e 70 64 62 } //FGT7t.pdb  3
		$a_80_1 = {53 65 74 49 43 4d 4d 6f 64 65 } //SetICMMode  3
		$a_80_2 = {4e 64 72 43 6c 65 61 72 4f 75 74 50 61 72 61 6d 65 74 65 72 73 } //NdrClearOutParameters  3
		$a_80_3 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  3
		$a_80_4 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  3
		$a_80_5 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 64 64 72 65 73 73 } //LdrGetProcedureAddress  3
		$a_80_6 = {47 44 49 33 32 2e 64 6c 6c } //GDI32.dll  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win64_Dridex_AS_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.AS!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c2 b9 40 00 00 00 83 e0 3f 2b c8 33 c0 48 d3 c8 b9 20 00 00 00 48 33 c2 f3 48 ab 48 8b 7c 24 08 b0 01 c3 } //10
		$a_01_1 = {41 8b c2 b9 40 00 00 00 83 e0 3f 2b c8 48 d3 cf 49 33 fa 4b 87 bc f7 00 ca 09 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}