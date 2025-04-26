
rule Ransom_Win64_Basta_AD_MTB{
	meta:
		description = "Ransom:Win64/Basta.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {48 89 9c 24 80 00 00 00 44 0f be d1 33 db 41 0f b7 ca 66 c7 45 b8 ?? 00 66 83 f1 ?? 66 89 5d ea 41 0f b7 d2 66 89 4d be 66 83 f2 ?? 66 89 4d c6 41 0f b7 c2 66 89 55 c2 66 83 f0 ?? 66 89 55 d0 66 89 45 ba 45 0f b7 c2 66 41 83 f0 ?? 41 0f b7 ca 41 0f b7 d2 66 44 89 45 c8 66 83 f1 ?? 66 44 89 45 cc 66 83 f2 ?? 66 89 4d d6 41 0f b7 c2 66 89 55 da 66 83 f0 ?? 66 89 4d dc 66 89 45 bc 45 0f b7 ca 66 41 83 f1 ?? 66 44 89 45 e2 41 0f b7 c2 66 89 55 e8 66 83 f0 ?? 66 44 89 4d c4 66 89 45 c0 4c 8d 45 ba } //100
		$a_03_2 = {41 0f b7 c2 66 44 89 4d ce 66 83 f0 ?? 66 44 89 4d e6 66 89 45 ca 33 d2 66 89 45 d2 b9 01 00 1f 00 41 0f b7 c2 66 83 f0 ?? 66 89 45 d4 41 0f b7 c2 66 83 f0 ?? 66 89 45 d8 41 0f b7 c2 66 83 f0 ?? 66 89 45 de 41 0f b7 c2 66 83 f0 ?? 66 41 83 f2 ?? 66 89 45 e0 66 44 89 55 e4 ff 15 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100) >=201
 
}