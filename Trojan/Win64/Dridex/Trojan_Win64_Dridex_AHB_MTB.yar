
rule Trojan_Win64_Dridex_AHB_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {44 46 44 44 2e 70 64 62 } //DFDD.pdb  3
		$a_80_1 = {43 4d 5f 47 65 74 5f 53 69 62 6c 69 6e 67 5f 45 78 } //CM_Get_Sibling_Ex  3
		$a_80_2 = {4b 46 36 34 2d 62 69 74 74 6f 34 49 6e 63 6f 67 6e 69 74 6f 49 4b 69 6e 66 } //KF64-bitto4IncognitoIKinf  3
		$a_80_3 = {61 6e 64 61 70 70 6c 69 63 61 74 69 6f 6e 73 70 68 69 73 68 69 6e 67 5a 32 30 31 33 2c 53 74 6f 72 65 } //andapplicationsphishingZ2013,Store  3
		$a_80_4 = {7a 61 6e 54 68 65 6e 6f 77 58 72 38 } //zanThenowXr8  3
		$a_80_5 = {77 65 6c 63 6f 6d 65 67 4a 56 5a 70 61 74 63 68 2e 4f } //welcomegJVZpatch.O  3
		$a_80_6 = {55 52 4c 6f 74 68 65 72 57 53 74 61 62 6c 65 55 36 4d 66 61 69 6c 65 64 31 31 35 37 38 74 68 65 } //URLotherWStableU6Mfailed11578the  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}