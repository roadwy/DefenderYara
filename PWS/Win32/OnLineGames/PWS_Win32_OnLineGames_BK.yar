
rule PWS_Win32_OnLineGames_BK{
	meta:
		description = "PWS:Win32/OnLineGames.BK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 00 00 80 ff 90 01 02 ff 15 90 01 04 8b f8 83 ff ff 74 90 01 01 90 90 90 90 90 90 90 90 90 02 08 8d 90 01 02 56 50 ff 90 01 02 ff 90 01 02 57 ff 15 90 00 } //01 00 
		$a_03_1 = {68 e8 03 00 00 ff 15 90 01 04 ff 05 90 01 04 eb 90 00 } //01 00 
		$a_02_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 90 02 10 2e 69 6e 69 90 00 } //01 00 
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 20 73 3f 25 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}