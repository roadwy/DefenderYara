
rule Ransom_Win32_BastaLoader_LKA_MTB{
	meta:
		description = "Ransom:Win32/BastaLoader.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {63 70 70 5c 67 69 74 32 5c 55 6e 69 63 6f 64 65 20 52 65 6c 65 61 73 65 5c [0-20] 2e 70 64 62 } //1
		$a_01_1 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //1 VisibleEntry
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}