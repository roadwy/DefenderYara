
rule PWS_Win32_OnLineGames_MQ{
	meta:
		description = "PWS:Win32/OnLineGames.MQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 f4 5b c6 45 f5 5e c6 45 f6 26 c6 45 f7 5e c6 45 f8 0d c6 45 f9 5e c6 45 fa 0a c6 45 fb 5d c6 45 fc 26 e8 } //01 00 
		$a_01_1 = {c6 85 4c ff ff ff 68 c6 85 4d ff ff ff 61 c6 85 4e ff ff ff 6e c6 85 4f ff ff ff 67 c6 85 50 ff ff ff 61 c6 85 51 ff ff ff 6d c6 85 52 ff ff ff 65 c6 85 53 ff ff ff 2e c6 85 54 ff ff ff 63 c6 85 55 ff ff ff 6f c6 85 56 ff ff ff 6d } //01 00 
		$a_01_2 = {26 73 65 63 72 65 74 41 6e 73 77 65 72 3d 00 } //01 00 
		$a_01_3 = {26 65 6d 61 69 6c 3d 00 26 72 65 71 75 65 73 74 54 79 70 65 3d 50 41 53 53 57 4f 52 44 5f 52 45 53 45 54 00 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 } //01 00 
		$a_01_4 = {79 61 6f 79 61 6f 32 35 } //00 00 
	condition:
		any of ($a_*)
 
}