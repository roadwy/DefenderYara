
rule Ransom_Win32_StopCrypt_MZK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 75 0c c7 05 90 02 08 33 75 f8 89 75 f4 8b 45 f4 01 05 90 02 04 8b 45 f0 2b fe 8b f7 c1 e6 90 02 01 03 75 e8 03 c7 81 3d 90 02 04 be 01 00 00 89 45 0c 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_StopCrypt_MZK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 c1 e8 90 01 01 89 45 ec 8b 45 ec 03 45 d4 89 45 ec 8b 45 e4 33 45 f0 89 45 e4 8b 45 e4 33 45 ec 89 45 e4 8b 45 e4 29 45 d0 ff 75 d8 8d 45 e8 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}