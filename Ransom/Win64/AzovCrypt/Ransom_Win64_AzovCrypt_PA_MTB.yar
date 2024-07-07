
rule Ransom_Win64_AzovCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/AzovCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 c7 c1 e0 3f 00 00 41 b9 13 5c 01 00 41 ba 00 92 81 92 48 ff c9 8a 14 08 44 30 ca 88 14 08 41 81 ea e2 6f 02 00 45 01 d1 41 81 c1 e2 6f 02 00 41 81 c2 e2 6f 02 00 41 d1 c1 48 85 c9 75 90 02 04 74 90 02 04 e8 90 02 10 e9 90 02 04 01 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}