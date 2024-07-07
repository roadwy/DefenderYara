
rule Trojan_Win32_Dridex_PB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {44 61 72 74 69 6e 67 44 6c 75 67 69 6e 5a 32 30 31 35 } //1 DartingDluginZ2015
		$a_81_1 = {48 65 32 44 6f 6f 67 6c 65 42 39 78 } //1 He2DoogleB9x
		$a_81_2 = {6e 75 6d 62 65 72 74 68 65 6d } //1 numberthem
		$a_81_3 = {44 44 64 65 66 61 75 6c 74 73 } //1 DDdefaults
		$a_81_4 = {6e 6e 6e 76 65 70 76 6d 64 67 68 2e 64 6c 6c } //1 nnnvepvmdgh.dll
		$a_81_5 = {66 70 6d 76 70 70 70 2e 70 64 62 } //1 fpmvppp.pdb
		$a_81_6 = {4f 72 61 63 6c 65 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //1 Oracle Corporation
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_Win32_Dridex_PB_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 6e 6e 76 65 70 76 6d 64 67 68 2e 64 6c 6c } //1 nnnvepvmdgh.dll
		$a_01_1 = {46 47 45 52 4e 2e 70 64 62 } //1 FGERN.pdb
		$a_01_2 = {78 00 32 00 6f 00 74 00 66 00 62 00 2e 00 64 00 6c 00 6c 00 } //1 x2otfb.dll
		$a_03_3 = {81 f1 80 8e b2 16 8b 94 24 90 01 04 8b b4 24 90 01 04 8b 7c 24 90 01 01 89 bc 24 90 01 04 89 8c 24 90 01 04 89 e1 90 02 25 8b 45 90 01 01 8b 8c 24 90 01 04 01 c8 8a 9c 24 90 01 04 b7 cb 28 df 88 bc 24 90 01 04 89 84 24 90 01 04 8b 44 24 90 01 01 35 25 0a fc 52 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=5
 
}