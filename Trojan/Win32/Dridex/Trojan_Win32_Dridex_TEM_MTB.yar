
rule Trojan_Win32_Dridex_TEM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.TEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_00_0 = {44 e0 52 79 9b 79 f1 3b eb 4c 40 53 45 7e a4 25 12 01 dc 10 a5 84 b6 07 8c 2a 29 cf 51 71 30 9e 78 f4 b2 fa cf 65 72 9b 6b cd 8c d3 91 1e a4 59 92 01 dc fc 24 51 36 26 ac 2a f5 02 50 90 7c ea } //10
		$a_80_1 = {52 70 6b 64 65 72 33 33 36 } //Rpkder336  3
		$a_80_2 = {46 47 45 52 4e 2e 70 64 62 } //FGERN.pdb  3
		$a_80_3 = {79 31 38 39 31 74 68 65 57 61 73 73 65 72 76 65 64 6d 34 } //y1891theWasservedm4  2
		$a_80_4 = {47 67 6f 6c 66 65 72 41 42 63 6f 70 79 76 65 72 73 69 6f 6e 74 6f 70 61 73 73 76 69 64 65 6f } //GgolferABcopyversiontopassvideo  2
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=20
 
}