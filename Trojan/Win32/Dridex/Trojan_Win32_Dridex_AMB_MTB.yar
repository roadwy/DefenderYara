
rule Trojan_Win32_Dridex_AMB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {8e 13 fa 26 54 57 3f 5c 48 71 8e bb 39 a7 fb f6 12 40 59 bc 02 a2 ae 57 4b 58 93 ef 74 2c 99 4b 2e 13 da 59 40 b7 0b 5c 48 71 7a 3b 39 bb fc f7 45 21 78 } //10
		$a_80_1 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //OutputDebugStringA  3
		$a_80_2 = {43 72 65 61 74 65 53 74 72 65 61 6d 4f 6e 48 47 6c 6f 62 61 6c } //CreateStreamOnHGlobal  3
		$a_81_3 = {23 3a 23 5c 23 45 23 54 23 50 23 2e 23 58 23 } //1 #:#\#E#T#P#.#X#
		$a_81_4 = {23 50 23 45 23 45 23 54 23 50 23 2e 23 58 23 } //1 #P#E#E#T#P#.#X#
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=8
 
}