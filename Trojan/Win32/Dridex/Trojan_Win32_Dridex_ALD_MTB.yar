
rule Trojan_Win32_Dridex_ALD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ALD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 } //LdrGetProcedureA  3
		$a_80_1 = {52 70 6b 64 65 72 33 33 36 } //Rpkder336  3
		$a_80_2 = {46 47 54 4e 7c 46 47 54 23 52 36 35 2e 70 64 62 } //FGTN|FGT#R65.pdb  3
		$a_80_3 = {57 33 61 6e 64 32 30 31 31 2c 39 6f 6e 6a 4a 32 30 31 33 2c 32 73 } //W3and2011,9onjJ2013,2s  3
		$a_80_4 = {65 6e 61 62 6c 65 64 68 75 6e 6c 69 6b 65 62 6f 73 74 6f 6e 66 71 34 33 70 68 6f 65 6e 69 78 } //enabledhunlikebostonfq43phoenix  3
		$a_80_5 = {47 6f 6f 67 6c 65 34 46 61 63 65 62 6f 6f 6b 6f 6e 65 4e 6f 6c 6f 61 64 75 70 64 61 74 65 73 47 } //Google4FacebookoneNoloadupdatesG  3
		$a_80_6 = {39 77 68 6f 62 72 6f 6e 63 6f 73 38 59 53 58 63 61 6c 6c 65 64 32 } //9whobroncos8YSXcalled2  3
		$a_80_7 = {4c 74 68 72 65 73 68 6f 6c 64 2e 33 39 73 61 67 61 69 6e 73 74 6f 66 55 62 75 74 47 55 74 68 65 } //Lthreshold.39sagainstofUbutGUthe  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}