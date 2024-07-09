
rule Ransom_Win64_Hive_DAA_MTB{
	meta:
		description = "Ransom:Win64/Hive.DAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 31 da 48 89 94 24 [0-04] 0f b6 54 08 0a 0f b7 44 08 08 35 bd 3c 00 00 66 89 84 24 [0-04] 80 f2 4d 88 94 24 4a 08 00 00 41 b9 0b 00 00 00 4c 89 e1 4c 89 fa 49 89 f0 e8 [0-04] 84 c0 48 8d 35 [0-04] 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}