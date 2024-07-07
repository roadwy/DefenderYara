
rule Trojan_Win32_Chapak_AHB_MTB{
	meta:
		description = "Trojan:Win32/Chapak.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 85 84 f8 ff ff a3 90 01 04 8b 8d 84 f8 ff ff 69 c9 24 31 00 00 8b 15 04 e0 06 01 2b d1 89 95 84 f8 ff ff 90 00 } //10
		$a_80_1 = {68 61 6c 66 2e 70 64 62 } //half.pdb  3
		$a_80_2 = {42 61 74 74 68 65 69 72 } //Battheir  3
		$a_80_3 = {43 6f 72 6e 65 72 66 61 6d 69 6c 79 } //Cornerfamily  3
		$a_80_4 = {57 69 66 65 66 6f 6c 6c 6f 77 } //Wifefollow  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}