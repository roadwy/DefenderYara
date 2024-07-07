
rule Trojan_Win32_Dridex_KA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {8b b3 37 92 66 db 02 5e aa 37 1e 47 e4 5f 3b d9 61 38 fc 2d 9b 64 55 fd 1e 8b 22 cd e0 e4 8d f4 eb 7f 37 12 9a bc 16 7d 2b 37 ff 33 44 7f 08 8d 15 38 9c f9 67 e3 09 b1 fe 8b 41 ae 60 84 } //10
		$a_80_1 = {45 46 52 45 36 35 2e 70 64 62 } //EFRE65.pdb  3
		$a_80_2 = {74 74 74 74 33 32 } //tttt32  3
		$a_80_3 = {65 73 74 61 70 70 } //estapp  3
		$a_80_4 = {57 61 6c 6c 6f 77 69 6e 67 74 } //Wallowingt  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}