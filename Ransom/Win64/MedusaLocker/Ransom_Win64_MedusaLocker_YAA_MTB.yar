
rule Ransom_Win64_MedusaLocker_YAA_MTB{
	meta:
		description = "Ransom:Win64/MedusaLocker.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 8d 79 08 41 8b c8 41 8b c2 83 e0 3f 2b c8 49 8b 47 08 48 8b 10 41 8b c0 48 d3 ca 49 33 d2 49 89 11 48 8b 15 ?? ?? ?? ?? 8b ca 83 e1 3f 2b c1 8a c8 49 8b 07 48 d3 ce 48 33 f2 48 8b 08 48 89 31 41 8b c8 } //2
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 41 00 49 00 44 00 4d 00 45 00 4d 00 45 00 53 00 } //1 SOFTWARE\PAIDMEMES
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}