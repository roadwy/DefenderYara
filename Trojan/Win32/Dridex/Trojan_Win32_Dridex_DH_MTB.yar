
rule Trojan_Win32_Dridex_DH_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {74 74 74 74 33 32 } //tttt32  3
		$a_80_1 = {72 72 70 6f 6b 64 6d 67 6e 6e } //rrpokdmgnn  3
		$a_80_2 = {46 6e 6c 6f 64 65 72 54 72 52 70 70 65 65 } //FnloderTrRppee  3
		$a_80_3 = {52 52 47 54 59 59 2e 70 64 62 } //RRGTYY.pdb  3
		$a_80_4 = {72 63 6f 6e 73 74 69 74 75 65 6e 63 79 2e 35 54 61 62 76 61 66 74 65 72 70 72 6f 74 6f 63 6f 6c 31 31 2c 61 6e 79 32 31 31 32 } //rconstituency.5Tabvafterprotocol11,any2112  3
		$a_80_5 = {56 6f 50 6f 6c 69 63 79 2e 31 38 39 61 6e 64 74 6f 52 75 72 61 61 73 64 66 67 68 } //VoPolicy.189andtoRuraasdfgh  3
		$a_80_6 = {74 68 65 31 67 74 68 65 79 66 75 6e 63 74 69 6f 6e 73 61 73 64 } //the1gtheyfunctionsasd  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}