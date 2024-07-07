
rule Trojan_Win32_Dridex_AQ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {72 72 70 69 6f 64 65 2e 70 64 62 } //rrpiode.pdb  3
		$a_80_1 = {6f 6e 75 70 6b 72 65 61 73 6f 6e 69 6e 67 43 68 72 6f 6d 65 32 52 4c 5a 63 49 6e 74 65 72 6e 65 74 32 30 30 38 2e 32 38 } //onupkreasoningChrome2RLZcInternet2008.28  3
		$a_80_2 = {6d 6f 64 65 66 72 6f 6d 41 62 72 6f 77 73 65 72 2e 59 47 } //modefromAbrowser.YG  3
		$a_80_3 = {75 73 61 67 65 64 61 79 2c 61 43 62 61 63 74 65 72 69 6f 6c 6f 67 79 70 68 6f 65 6e 69 78 77 } //usageday,aCbacteriologyphoenixw  3
		$a_80_4 = {46 69 6e 64 46 69 72 73 74 56 6f 6c 75 6d 65 4d 6f 75 6e 74 50 6f 69 6e 74 41 } //FindFirstVolumeMountPointA  3
		$a_80_5 = {54 47 38 31 2d 62 69 74 74 6f 34 49 6e 63 6f 67 6e 69 74 6f 49 4b 69 6e 66 } //TG81-bitto4IncognitoIKinf  3
		$a_80_6 = {4b 35 6e 6c 6e 6f 74 } //K5nlnot  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}