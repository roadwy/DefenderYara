
rule Trojan_Win32_Dridex_AMD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {7a 69 a5 0f 08 e8 c2 8b af 0b 63 78 98 28 fd 1b 52 6b 23 a7 df 08 a4 dd 49 6d 01 94 34 ca 1c 2b 7a 09 b9 0f 1c 9c 76 57 8f 0b 64 79 19 88 1c bb 33 9f 23 28 ff e8 44 dd 16 ec b5 b3 35 e9 e8 3f } //10
		$a_80_1 = {2c 2c 73 2c 2c 70 70 2c 2c 2c 65 } //,,s,,pp,,,e  3
		$a_80_2 = {66 66 66 70 34 2e 70 64 62 } //fffp4.pdb  3
		$a_81_3 = {23 3a 23 5c 23 45 23 54 23 50 23 2e 23 58 23 } //1 #:#\#E#T#P#.#X#
		$a_81_4 = {23 50 23 45 23 45 23 54 23 50 23 2e 23 58 23 } //1 #P#E#E#T#P#.#X#
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=8
 
}