
rule Trojan_Win64_Dridex_AH_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 08 00 00 "
		
	strings :
		$a_80_0 = {73 64 6d 66 7c 65 72 2e 70 64 62 } //sdmf|er.pdb  3
		$a_80_1 = {43 79 75 3a 2d 23 21 } //Cyu:-#!  3
		$a_80_2 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  3
		$a_80_3 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  3
		$a_80_4 = {66 70 72 6f 6c 67 37 36 2e 5f 6c } //fprolg76._l  3
		$a_80_5 = {56 6b 4b 65 79 53 63 61 6e 41 } //VkKeyScanA  3
		$a_80_6 = {43 72 79 70 74 43 41 54 43 6c 6f 73 65 } //CryptCATClose  3
		$a_80_7 = {4f 70 65 6e 50 65 72 73 6f 6e 61 6c 54 72 75 73 74 44 42 44 69 61 6c 6f 67 } //OpenPersonalTrustDBDialog  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=21
 
}