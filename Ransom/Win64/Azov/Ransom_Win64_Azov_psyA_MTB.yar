
rule Ransom_Win64_Azov_psyA_MTB{
	meta:
		description = "Ransom:Win64/Azov.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_03_0 = {ff d0 48 c7 c1 90 01 03 00 4c 8d 0d 90 01 03 ff 48 ff c9 41 8a 14 09 88 14 08 48 85 c9 75 f1 48 c7 c1 90 01 03 00 41 b9 90 01 03 00 41 ba 00 92 81 92 48 ff c9 8a 14 08 44 30 ca 88 14 08 41 81 ea e2 6f 02 00 45 01 d1 41 81 c1 e2 6f 02 00 41 81 c2 e2 6f 02 00 41 d1 c1 48 85 c9 75 0b 74 0f e8 fb ff ff ff df 6f 84 e9 75 c7 f3 34 01 00 75 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}