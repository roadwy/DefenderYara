
rule Ransom_Win32_StopCrypt_PBV_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d0 89 54 24 90 01 01 8b 44 24 90 01 01 c1 e8 05 89 44 24 90 01 01 8b 44 24 90 01 01 33 4c 24 90 01 01 03 44 24 90 01 01 c7 05 90 02 0a 33 c1 81 3d 90 02 0a 89 44 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}