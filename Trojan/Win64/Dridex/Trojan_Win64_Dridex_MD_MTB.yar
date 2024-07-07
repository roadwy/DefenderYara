
rule Trojan_Win64_Dridex_MD_MTB{
	meta:
		description = "Trojan:Win64/Dridex.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {78 70 62 2e 70 64 62 } //xpb.pdb  3
		$a_80_1 = {47 65 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 49 6e 66 6f 41 } //GetUrlCacheEntryInfoA  3
		$a_80_2 = {43 4d 5f 47 65 74 5f 53 69 62 6c 69 6e 67 5f 45 78 } //CM_Get_Sibling_Ex  3
		$a_80_3 = {53 61 66 65 72 43 72 65 61 74 65 4c 65 76 65 6c } //SaferCreateLevel  3
		$a_80_4 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  3
		$a_80_5 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  3
		$a_80_6 = {47 65 74 53 61 76 65 46 69 6c 65 4e 61 6d 65 41 } //GetSaveFileNameA  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}