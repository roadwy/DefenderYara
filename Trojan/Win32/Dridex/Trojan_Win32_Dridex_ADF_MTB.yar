
rule Trojan_Win32_Dridex_ADF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ADF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {01 00 c5 d0 18 c5 2e 26 e1 ca a9 f1 9e 12 14 1b c3 f0 2a cf ec ee 46 18 c4 ab 57 a5 51 40 7c fe 4a 78 b1 f0 18 45 fb 07 e1 ca 75 f2 bd 12 34 e7 a3 f0 a9 4f b9 4e 45 f9 e4 de 43 91 51 2c 7c fd } //10
		$a_80_1 = {2d 2d 73 2d 2d 70 70 2d 2d 2d 2d } //--s--pp----  3
		$a_80_2 = {47 73 70 2e 70 64 62 } //Gsp.pdb  3
		$a_81_3 = {23 3a 23 5c 23 45 23 54 23 50 23 2e 23 58 23 } //1 #:#\#E#T#P#.#X#
		$a_81_4 = {23 50 23 45 23 45 23 54 23 50 23 2e 23 58 23 } //1 #P#E#E#T#P#.#X#
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=8
 
}