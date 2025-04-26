
rule Ransom_Win32_Gandcrab_C_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {ff ff eb 08 e8 ?? ?? ?? ?? 30 04 37 83 ee 01 79 f3 5f 5e c2 04 00 } //2
		$a_00_1 = {00 40 3d 00 01 00 00 75 f2 33 ff 33 f6 89 3d } //2
		$a_00_2 = {63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e } //1 cannot be run in DOS mode.
		$a_00_3 = {21 54 68 69 73 20 70 72 6f 67 72 61 6d } //-1 !This program
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-1) >=4
 
}