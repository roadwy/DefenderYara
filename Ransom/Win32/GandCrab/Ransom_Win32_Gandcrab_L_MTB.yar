
rule Ransom_Win32_Gandcrab_L_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {21 54 68 69 73 20 70 72 6f 67 72 61 6d } //-1 !This program
		$a_00_1 = {63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e } //1 cannot be run in DOS mode.
		$a_02_2 = {6a 00 ff d6 e8 ?? ?? ff ff 8b 4c 24 0c 30 04 39 83 ef 01 79 e3 ff 15 } //1
		$a_00_3 = {00 40 3d 00 01 00 00 75 f2 } //1
	condition:
		((#a_00_0  & 1)*-1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}