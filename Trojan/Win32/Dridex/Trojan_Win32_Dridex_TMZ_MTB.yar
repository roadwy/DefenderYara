
rule Trojan_Win32_Dridex_TMZ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.TMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_00_0 = {c2 15 36 da f4 df 85 92 a6 00 bb 55 d6 3e 21 4b de 12 fd cb 2a e8 70 ab 01 cc c1 af 47 00 d4 3a 22 16 16 7a 28 c0 99 a6 a6 20 db d5 8a 1e 40 ca de 91 31 ab ca b5 5c 97 80 4c f5 9b c7 00 d4 b9 } //10
		$a_80_1 = {52 70 6b 64 65 72 33 33 36 } //Rpkder336  3
		$a_80_2 = {46 47 45 52 4e 2e 70 64 62 } //FGERN.pdb  3
		$a_80_3 = {49 6e 61 6e 64 43 68 72 6f 6d 65 43 62 65 68 61 76 65 6d 6e 75 6d 62 65 72 76 63 6f 6e 73 74 69 74 75 65 6e 63 79 2e 35 } //InandChromeCbehavemnumbervconstituency.5  2
		$a_80_4 = {47 67 6f 6c 66 65 72 41 42 63 6f 70 79 76 65 72 73 69 6f 6e 74 6f 70 61 73 73 76 69 64 65 6f } //GgolferABcopyversiontopassvideo  2
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=20
 
}