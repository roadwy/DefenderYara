
rule Ransom_Win32_PlayCrypt_MP_MTB{
	meta:
		description = "Ransom:Win32/PlayCrypt.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 54 31 03 83 ef 04 0f b6 4c 31 02 c1 e2 08 0b d1 8b 4d fc c1 e2 08 0f b6 4c 31 01 0b d1 8b 4d fc c1 e2 08 0f b6 0c 31 83 c6 04 0b d1 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_PlayCrypt_MP_MTB_2{
	meta:
		description = "Ransom:Win32/PlayCrypt.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 8b 44 15 f4 66 83 e8 01 b9 02 00 00 00 6b d1 00 66 89 44 15 f4 b8 02 00 00 00 6b c8 00 66 8b 54 0d e4 66 83 c2 01 b8 02 00 00 00 6b c8 00 66 89 54 0d e4 8b 95 ac fd ff ff 83 c2 01 89 95 ac fd ff ff 8b 85 94 fd ff ff 83 c0 01 89 85 94 fd } //01 00 
		$a_01_1 = {8b 45 94 89 45 90 8b 4d 20 51 8b 55 1c 52 8b 45 18 50 8b 4d 14 51 8b 55 10 52 8b 45 0c 50 8b 4d 08 51 } //00 00 
	condition:
		any of ($a_*)
 
}