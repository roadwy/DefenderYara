
rule Ransom_Win32_PrincessLocker_A{
	meta:
		description = "Ransom:Win32/PrincessLocker.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 45 fc 02 8d 45 90 01 01 83 7d 90 01 01 10 0f 43 45 90 01 01 50 53 ff 15 90 01 04 68 00 00 00 f0 6a 18 68 90 01 04 6a 00 8b f8 68 90 01 04 ff d7 90 00 } //01 00 
		$a_03_1 = {3a 00 5c 00 50 ff 15 90 01 04 83 f8 03 74 09 83 f8 04 0f 85 90 01 02 00 00 6a 00 6a 00 6a 00 6a 00 8d 45 e4 50 ff 15 90 01 04 85 c0 0f 84 90 00 } //01 00 
		$a_03_2 = {83 c3 1a 83 c0 1a 89 9d 90 01 02 ff ff 89 85 90 01 02 ff ff 81 fb 46 9a 00 00 0f 82 90 01 02 ff ff 8b 85 90 01 02 ff ff 83 f8 08 72 13 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}