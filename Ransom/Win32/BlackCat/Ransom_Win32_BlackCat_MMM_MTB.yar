
rule Ransom_Win32_BlackCat_MMM_MTB{
	meta:
		description = "Ransom:Win32/BlackCat.MMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 07 30 4f 01 0f b6 4c 24 2b 30 57 02 0f b6 54 24 2c 30 4f 03 0f b6 4c 24 2d 30 57 04 0f b6 54 24 2e 30 4f 05 0f b6 4c 24 2f 30 57 06 0f b6 54 24 ?? 30 4f 07 0f b6 4c 24 31 30 57 08 } //1
		$a_03_1 = {0f b6 54 24 32 30 4f 09 0f b6 4c 24 33 30 57 0a 0f b6 54 24 34 30 4f 0b 0f b6 4c 24 35 30 57 0c 0f b6 54 24 36 30 4f 0d 0f b6 4c 24 ?? 30 57 0e 30 4f 0f 8b 4c 24 10 83 c7 10 83 c1 10 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}