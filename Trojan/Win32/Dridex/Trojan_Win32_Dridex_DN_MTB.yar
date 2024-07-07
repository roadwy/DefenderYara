
rule Trojan_Win32_Dridex_DN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 04 00 00 "
		
	strings :
		$a_00_0 = {26 00 90 48 8d 4b 18 48 83 c4 30 5b 48 ff } //10
		$a_02_1 = {8b c6 c1 e0 06 2b c6 b9 ff ff 00 00 2b c8 83 3d 90 01 04 05 57 0f b7 c1 77 15 90 00 } //10
		$a_80_2 = {45 69 74 68 65 72 6e 6f 74 68 69 6e 67 } //Eithernothing  3
		$a_80_3 = {53 6d 69 6c 65 73 63 68 6f 6f 6c } //Smileschool  3
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=26
 
}