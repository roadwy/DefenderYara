
rule Trojan_Win64_DllInject_C_MTB{
	meta:
		description = "Trojan:Win64/DllInject.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {ff c9 8b c1 d1 e8 0b c8 8b c1 c1 e8 02 0b c8 8b c1 c1 e8 04 0b c8 8b c1 c1 e8 08 0b c8 8b c1 c1 e8 10 0b c1 ff c0 } //1
		$a_80_1 = {42 6c 61 63 6b 42 6f 6e 65 2e 73 79 73 } //BlackBone.sys  1
		$a_80_2 = {4e 69 76 65 73 72 6f 4c 6f 61 64 65 72 2e 70 64 62 } //NivesroLoader.pdb  1
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}