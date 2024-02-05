
rule Backdoor_Win32_AdultChat_A{
	meta:
		description = "Backdoor:Win32/AdultChat.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f0 46 8d 04 36 83 c0 03 24 fc e8 90 01 02 ff ff 8b fc 56 57 6a ff ff 75 08 66 83 27 00 6a 00 6a 00 ff 15 90 01 04 85 c0 75 22 8b 35 90 01 04 ff d6 85 c0 74 0e ff d6 25 ff ff 00 00 0d 00 00 07 80 eb 02 33 c0 50 90 00 } //01 00 
		$a_02_1 = {55 8b ec 83 3d 90 01 04 00 75 1c 68 90 01 04 68 90 01 04 e8 90 01 02 ff ff 85 c0 74 09 83 0d 90 01 04 ff eb 22 a1 90 01 04 83 f8 ff 75 07 b8 49 00 00 80 eb 11 ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff d0 5d c2 14 00 83 3d 90 01 04 00 75 1c 68 90 01 04 68 90 01 04 e8 90 01 02 ff ff 85 c0 74 09 83 0d 90 01 04 ff eb 17 a1 90 01 04 83 f8 ff 75 07 b8 49 00 00 80 eb 06 ff 74 24 04 ff d0 c2 04 00 90 00 } //01 00 
		$a_00_2 = {3c 4d 45 52 43 48 3e 00 3c 50 48 4f 4e 45 3e 00 3c 4c 49 4d 49 54 3e 00 3c 50 52 49 43 45 3e 00 3c 70 3e } //00 00 
	condition:
		any of ($a_*)
 
}