
rule Ransom_Win32_BastaLoader_LK_MTB{
	meta:
		description = "Ransom:Win32/BastaLoader.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 55 d8 83 c2 01 89 55 d8 8b 45 d8 3b 45 d0 7d 1a 8b 4d c0 03 4d d8 89 4d bc 8b 55 bc 52 8d 4d b0 e8 90 01 04 89 45 a0 eb d5 90 00 } //1
		$a_03_1 = {6a 00 6a 40 68 00 30 00 00 90 01 06 50 6a 00 e8 90 00 } //1
		$a_01_2 = {8b 45 d4 8b 4d d0 8a 11 88 10 8b 45 fc 8b 08 89 4d cc 8b 55 fc 8b 02 83 c0 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}