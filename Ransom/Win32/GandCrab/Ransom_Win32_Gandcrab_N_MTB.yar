
rule Ransom_Win32_Gandcrab_N_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 e8 ?? ?? ff ff 30 04 37 8d 85 ?? ?? ff ff 50 6a 00 ff 15 ?? ?? ?? 00 46 3b 75 08 7c d5 8b 4d fc 5f 33 cd 5e e8 ?? ?? ff ff c9 c2 04 00 } //1
		$a_02_1 = {c1 e8 10 25 ff 7f 00 00 c3 90 0a 1f 00 a1 ?? ?? ?? 00 69 c0 ?? ?? ?? 00 05 ?? ?? ?? 00 a3 ?? ?? ?? 00 c1 e8 10 25 ff 7f 00 00 c3 } //1
		$a_00_2 = {21 54 68 69 73 20 70 72 6f 67 72 61 6d } //-1 !This program
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*-1) >=2
 
}