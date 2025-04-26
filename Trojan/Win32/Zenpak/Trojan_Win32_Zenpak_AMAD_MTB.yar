
rule Trojan_Win32_Zenpak_AMAD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {41 3a 5c 4c 71 4f 70 68 32 54 5c 44 68 66 33 56 66 70 37 53 5c 35 69 2e 70 64 62 } //A:\LqOph2T\Dhf3Vfp7S\5i.pdb  1
		$a_80_1 = {73 75 62 64 75 65 43 67 6f 64 39 43 72 65 65 70 65 74 68 77 73 74 61 72 73 66 6f 77 6c } //subdueCgod9Creepethwstarsfowl  1
		$a_80_2 = {79 42 62 44 67 6f 64 73 68 65 2e 64 } //yBbDgodshe.d  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}