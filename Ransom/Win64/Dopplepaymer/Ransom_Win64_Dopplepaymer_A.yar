
rule Ransom_Win64_Dopplepaymer_A{
	meta:
		description = "Ransom:Win64/Dopplepaymer.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 89 c8 32 c9 44 89 c2 fe c1 d1 ea 89 d0 35 20 83 b8 ed 41 f7 c0 01 00 00 00 41 89 c0 44 0f 44 c2 80 f9 08 7c df 47 89 04 8a 49 ff c1 49 81 f9 00 01 00 00 7c ca } //01 00 
		$a_01_1 = {41 89 c2 ff ca 45 0f b6 08 4d 33 d1 45 0f b6 da 49 ff c0 c1 e8 08 42 33 04 99 83 fa ff 75 e1 4c 89 45 18 f7 d0 } //00 00 
	condition:
		any of ($a_*)
 
}