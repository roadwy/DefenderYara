
rule Ransom_Win32_BastaLoader_LKA_MTB{
	meta:
		description = "Ransom:Win32/BastaLoader.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 70 70 5c 67 69 74 32 5c 55 6e 69 63 6f 64 65 20 52 65 6c 65 61 73 65 5c 90 02 20 2e 70 64 62 90 00 } //01 00 
		$a_01_1 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //00 00  VisibleEntry
	condition:
		any of ($a_*)
 
}