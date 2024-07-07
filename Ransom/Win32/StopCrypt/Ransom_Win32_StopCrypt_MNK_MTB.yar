
rule Ransom_Win32_StopCrypt_MNK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 fa d3 ea 89 7c 24 24 89 54 24 14 8b 44 24 34 01 44 24 14 8b 44 24 24 31 44 24 10 8b 4c 24 10 33 4c 24 14 8d 44 24 28 89 4c 24 10 e8 90 01 04 8d 44 24 20 e8 90 01 04 83 eb 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Ransom_Win32_StopCrypt_MNK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 c7 45 fc 90 02 04 8b 45 0c 8b 4d fc d3 e8 8b 4d 08 89 01 8b e5 5d c2 90 00 } //1
		$a_03_1 = {55 8b ec 51 c7 45 fc 90 02 04 8b 45 10 01 45 fc 8b 45 0c 33 45 fc 8b 4d 08 89 01 8b e5 5d c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}