
rule Ransom_Win32_StopCrypt_MWK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d1 31 55 90 01 01 8b 55 90 1b 00 8d 8d 90 01 04 e8 90 01 04 83 3d 90 01 05 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Ransom_Win32_StopCrypt_MWK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 29 45 f4 25 90 02 04 8b 45 f4 8b 55 fc 8b c8 03 d0 c1 e9 90 02 01 03 4d d8 c1 e0 90 02 01 03 45 dc 52 89 4d f8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}