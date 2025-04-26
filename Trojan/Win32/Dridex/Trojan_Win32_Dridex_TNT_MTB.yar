
rule Trojan_Win32_Dridex_TNT_MTB{
	meta:
		description = "Trojan:Win32/Dridex.TNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_00_0 = {18 90 86 27 4d 0c 6b 27 87 52 82 9c 04 5f 99 54 8e ee a2 4b 9a 42 26 d4 7b f5 c8 48 c7 16 04 06 4b 5c a5 f4 cd ac 6b 08 67 d2 02 9c 64 5e f9 f4 c1 ee c1 18 1b 2e a6 d4 9a 76 14 48 a7 e2 f0 06 } //10
		$a_80_1 = {52 70 6b 64 65 72 33 33 36 } //Rpkder336  3
		$a_80_2 = {46 47 45 52 4e 2e 70 64 62 } //FGERN.pdb  3
		$a_80_3 = {79 31 38 39 31 74 68 65 57 61 73 73 65 72 76 65 64 6d 34 } //y1891theWasservedm4  2
		$a_80_4 = {49 6e 61 6e 64 43 68 72 6f 6d 65 43 62 65 68 61 76 65 6d 6e 75 6d 62 65 72 76 63 6f 6e 73 74 69 74 75 65 6e 63 79 2e 35 } //InandChromeCbehavemnumbervconstituency.5  2
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=20
 
}