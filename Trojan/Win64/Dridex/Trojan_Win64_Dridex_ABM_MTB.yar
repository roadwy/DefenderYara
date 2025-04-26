
rule Trojan_Win64_Dridex_ABM_MTB{
	meta:
		description = "Trojan:Win64/Dridex.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {6f 43 61 6e 61 72 79 39 64 73 75 70 75 6e 64 65 72 6f 6e 62 61 73 65 64 58 } //oCanary9dsupunderonbasedX  3
		$a_80_1 = {4e 61 73 74 68 65 33 39 73 43 68 72 6f 6d 65 37 42 65 74 61 } //Nasthe39sChrome7Beta  3
		$a_80_2 = {4b 46 36 34 2d 62 69 74 74 6f 34 49 6e 63 6f 67 6e 69 74 6f 49 4b 69 6e 66 } //KF64-bitto4IncognitoIKinf  3
		$a_80_3 = {4b 35 6e 6c 6e 6f 74 } //K5nlnot  3
		$a_80_4 = {72 72 70 69 6f 64 65 2e 70 64 62 } //rrpiode.pdb  3
		$a_80_5 = {47 65 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 49 6e 66 6f 57 } //GetUrlCacheEntryInfoW  3
		$a_80_6 = {43 72 65 61 74 65 44 69 73 63 61 72 64 61 62 6c 65 42 69 74 6d 61 70 } //CreateDiscardableBitmap  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}