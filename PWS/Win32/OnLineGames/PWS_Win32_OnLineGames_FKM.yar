
rule PWS_Win32_OnLineGames_FKM{
	meta:
		description = "PWS:Win32/OnLineGames.FKM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 02 00 00 8d 85 90 01 02 ff ff 50 e8 90 01 02 ff ff 68 04 01 00 00 8d 85 90 01 02 ff ff 50 e8 90 01 02 ff ff 6a 05 68 90 01 04 8d 85 90 01 02 ff ff 50 e8 90 01 02 ff ff 90 00 } //01 00 
		$a_00_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6b 6e 6c 45 78 74 2e 64 6c 6c } //01 00 
		$a_00_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 44 72 69 76 65 72 73 5c 75 73 62 4b 65 79 49 6e 69 74 2e 73 79 73 } //00 00 
	condition:
		any of ($a_*)
 
}