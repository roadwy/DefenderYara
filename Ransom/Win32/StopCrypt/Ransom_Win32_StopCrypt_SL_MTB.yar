
rule Ransom_Win32_StopCrypt_SL_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f8 c1 ef 05 03 7d e8 c1 e0 04 03 45 e4 89 4d f8 33 f8 33 f9 89 7d 0c 8b 45 0c 01 05 90 01 04 8b 45 0c 29 45 08 8b 45 08 c1 e0 04 03 c6 89 45 f4 8b 45 08 03 45 f0 90 00 } //01 00 
		$a_03_1 = {51 c7 45 fc 90 01 04 8b 45 0c 90 90 01 45 fc 83 6d fc 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 31 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_StopCrypt_SL_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {55 8b ec 53 56 57 51 64 ff 35 30 00 00 00 58 8b 40 0c 8b 48 0c 8b 11 8b 41 30 6a 02 8b 7d 90 01 01 57 50 e8 90 01 01 00 00 00 85 c0 74 90 00 } //02 00 
		$a_03_1 = {55 8b ec 83 ec 90 01 01 53 56 57 8b 45 90 01 01 c6 00 00 83 65 90 01 01 00 e8 00 00 00 00 58 89 45 90 01 01 81 45 90 01 05 8b 45 90 01 01 8b 4d 90 01 01 89 48 90 01 01 8b 45 90 01 01 83 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}