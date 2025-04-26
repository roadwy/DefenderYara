
rule Trojan_Win32_Dridex_EVB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_00_0 = {c4 75 f8 71 bd 6b 49 7e 3f 54 b9 6b 7b ef a4 e6 a2 97 91 63 1a 6d 64 51 01 30 3b 0a 9f 39 c5 60 c4 94 18 11 dd 4c 49 92 73 d3 39 6b 7b ef f0 e5 d5 96 a5 03 ba 6d 18 b1 21 11 4f 8a be d9 79 60 } //10
		$a_80_1 = {52 70 6b 64 65 72 33 33 36 } //Rpkder336  3
		$a_80_2 = {46 47 45 52 4e 2e 70 64 62 } //FGERN.pdb  3
		$a_80_3 = {52 65 67 4f 76 65 72 72 69 64 65 50 72 65 64 65 66 4b 65 79 } //RegOverridePredefKey  2
		$a_80_4 = {52 61 73 47 65 74 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 61 74 69 73 74 69 63 73 } //RasGetConnectionStatistics  2
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=20
 
}