
rule Ransom_Win32_StopCrypt_MRK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e0 89 45 fc 8b 45 d8 01 45 fc 8b 4d d4 8b c2 c1 e8 90 02 01 89 45 ec 8d 45 ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_StopCrypt_MRK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 8b fe d3 ef 89 45 f4 03 7d d8 33 f8 81 fa 90 02 04 75 90 00 } //01 00 
		$a_03_1 = {8b 4d dc 8b c3 c1 e8 90 01 01 89 45 f0 8d 45 f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}