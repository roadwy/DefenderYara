
rule Ransom_Win32_StopCrypt_MWK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d1 31 55 ?? 8b 55 90 1b 00 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Ransom_Win32_StopCrypt_MWK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 29 45 f4 25 [0-04] 8b 45 f4 8b 55 fc 8b c8 03 d0 c1 e9 [0-01] 03 4d d8 c1 e0 [0-01] 03 45 dc 52 89 4d f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}