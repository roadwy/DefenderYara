
rule Trojan_Win32_Dridex_EDC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_00_0 = {47 ba 29 9a a5 62 f5 4c 4a 2d a0 c4 db 0e fa 03 51 95 8c 48 9a 0f 1f 8f eb 03 33 5c a3 53 f3 cc 7b 3b 2a 19 d9 62 e1 19 6a f9 a0 d8 ef 0e fa 83 d1 95 0b 7c ba 0f 1f c3 eb 37 52 7b 03 33 26 cc } //10
		$a_80_1 = {52 70 6b 64 65 72 33 33 36 } //Rpkder336  3
		$a_80_2 = {46 47 45 52 4e 2e 70 64 62 } //FGERN.pdb  3
		$a_80_3 = {43 72 65 61 74 65 50 6f 69 6e 74 65 72 4d 6f 6e 69 6b 65 72 } //CreatePointerMoniker  2
		$a_80_4 = {43 72 65 61 74 65 53 74 72 65 61 6d 4f 6e 48 47 6c 6f 62 61 6c } //CreateStreamOnHGlobal  2
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=20
 
}