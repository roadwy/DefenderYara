
rule Trojan_Win32_Dridex_KS_MTB{
	meta:
		description = "Trojan:Win32/Dridex.KS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {89 9d ad ba 1e dc 49 4a ce 23 6b 29 c3 1b b9 fd 9b 1e 23 3e 80 f8 cd 98 c9 07 35 f4 78 d4 d2 cf 89 d1 c1 06 ff 7c 49 7d cd 0f 6a 3d 0f e7 99 fd 1b 1e 23 3e 4d 17 9a 18 69 bb 81 d4 58 88 1e 6f } //10
		$a_80_1 = {45 53 54 41 50 50 50 65 78 65 } //ESTAPPPexe  3
		$a_80_2 = {74 74 74 74 33 32 } //tttt32  3
		$a_80_3 = {52 70 6b 64 65 72 33 33 36 } //Rpkder336  3
		$a_80_4 = {66 70 6d 76 70 70 70 2e 70 64 62 } //fpmvppp.pdb  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}