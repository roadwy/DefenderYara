
rule Trojan_Win64_Dridex_AKN_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {4b 35 6e 6c 6e 6f 74 } //K5nlnot  3
		$a_80_1 = {6f 6e 75 70 6b 72 65 61 73 6f 6e 69 6e 67 43 68 72 6f 6d 65 32 52 4c 5a 63 49 6e 74 65 72 6e 65 74 32 30 30 38 2e 32 38 } //onupkreasoningChrome2RLZcInternet2008.28  3
		$a_80_2 = {72 72 70 69 6f 64 65 2e 70 64 62 } //rrpiode.pdb  3
		$a_80_3 = {62 6a 61 6b 65 74 75 63 6b 65 72 4a 69 6e 66 72 6f 6d 7a 47 } //bjaketuckerJinfromzG  3
		$a_80_4 = {4d 70 72 41 64 6d 69 6e 49 6e 74 65 72 66 61 63 65 54 72 61 6e 73 70 6f 72 74 41 64 64 } //MprAdminInterfaceTransportAdd  3
		$a_80_5 = {4b 46 36 34 2d 62 69 74 74 6f 34 49 6e 63 6f 67 6e 69 74 6f 49 4b 69 6e 66 } //KF64-bitto4IncognitoIKinf  3
		$a_80_6 = {74 43 61 74 61 72 74 39 64 73 74 70 75 6e 64 74 72 6f 6e 74 74 73 74 64 58 } //tCatart9dstpundtronttstdX  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}