
rule Trojan_Win32_Dridex_ANM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ANM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 "
		
	strings :
		$a_00_0 = {94 80 07 75 ab ee 4b 9d 2b 02 67 8d 84 14 9c 4d 00 1a e8 ee af d0 5f db eb 8a 47 e8 ba c4 8b ad 94 60 1b 61 ab ee 17 e9 4b 22 66 d9 65 94 69 99 33 1a 48 8e 30 4f 13 a7 6a aa 5b e8 ba 10 8b cd } //10
		$a_80_1 = {74 74 74 74 33 32 } //tttt32  4
		$a_80_2 = {46 62 6d 67 70 6f 64 34 33 } //Fbmgpod43  4
		$a_80_3 = {70 76 6c 64 62 2e 70 64 62 } //pvldb.pdb  4
		$a_80_4 = {47 67 6f 6c 66 65 72 41 42 63 6f 70 79 76 65 72 73 69 6f 6e 74 6f 70 61 73 73 76 69 64 65 6f } //GgolferABcopyversiontopassvideo  4
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*4+(#a_80_2  & 1)*4+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4) >=26
 
}