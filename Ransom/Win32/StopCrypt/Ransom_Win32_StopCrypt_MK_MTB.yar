
rule Ransom_Win32_StopCrypt_MK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 70 89 45 90 02 01 8b 85 b0 fe ff ff 01 45 90 1b 00 8b 7d 70 8b 4d 6c 33 5d 90 1b 00 d3 ef c7 05 90 02 08 03 bd a4 fe ff ff 33 fb 81 3d 90 02 06 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_StopCrypt_MK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e1 90 02 01 03 8d 90 02 02 ff ff 81 3d 90 02 06 00 00 90 13 8b 5d 90 02 01 03 d8 c1 e8 90 02 01 89 45 90 02 01 c7 05 90 02 08 8b 85 90 02 02 ff ff 01 45 90 02 01 81 3d 90 02 06 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_StopCrypt_MK_MTB_3{
	meta:
		description = "Ransom:Win32/StopCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {65 6e 63 72 79 70 74 69 6f 6e 77 69 6e 61 70 69 5c 53 61 6c 73 61 32 30 2e 69 6e 6c } //01 00 
		$a_81_1 = {62 6f 77 73 61 6b 6b 64 65 73 74 78 2e 74 78 74 } //01 00 
		$a_81_2 = {43 3a 5c 53 79 73 74 65 6d 49 44 5c 50 65 72 73 6f 6e 61 6c 49 44 2e 74 78 74 } //01 00 
		$a_81_3 = {54 69 6d 65 20 54 72 69 67 67 65 72 20 54 61 73 6b } //01 00 
		$a_81_4 = {54 72 69 67 67 65 72 31 } //01 00 
		$a_81_5 = {2d 2d 41 75 74 6f 53 74 61 72 74 } //01 00 
		$a_81_6 = {64 65 6c 73 65 6c 66 2e 62 61 74 } //01 00 
		$a_81_7 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //00 00 
	condition:
		any of ($a_*)
 
}