
rule Trojan_BAT_StealC_EZ_MTB{
	meta:
		description = "Trojan:BAT/StealC.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_81_0 = {47 61 73 74 72 61 65 61 20 42 6f 75 69 6c 6c 6f 6e 73 20 52 65 64 72 65 73 73 65 73 } //2 Gastraea Bouillons Redresses
		$a_81_1 = {53 69 70 68 6f 6e 61 67 65 73 20 41 70 6f 6d 6f 72 70 68 69 6e 65 20 50 61 72 61 66 6f 72 6d 73 } //2 Siphonages Apomorphine Paraforms
		$a_81_2 = {33 37 35 63 35 65 66 66 2d 30 36 35 30 2d 34 33 30 31 2d 38 35 65 66 2d 33 38 32 63 66 65 66 61 39 61 64 66 } //2 375c5eff-0650-4301-85ef-382cfefa9adf
		$a_81_3 = {41 49 4f 73 6e 63 6f 69 75 75 41 } //1 AIOsncoiuuA
		$a_81_4 = {69 6f 41 48 73 69 75 6a 78 68 62 69 41 49 6b 61 6f } //1 ioAHsiujxhbiAIkao
		$a_81_5 = {56 51 50 2e 65 78 65 } //1 VQP.exe
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=9
 
}