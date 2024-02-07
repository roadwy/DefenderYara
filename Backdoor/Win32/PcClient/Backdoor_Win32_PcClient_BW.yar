
rule Backdoor_Win32_PcClient_BW{
	meta:
		description = "Backdoor:Win32/PcClient.BW,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  \svchost.exe
		$a_00_1 = {4c 6f 61 64 50 72 6f 66 69 6c 65 } //01 00  LoadProfile
		$a_00_2 = {64 72 69 76 65 72 73 5c } //01 00  drivers\
		$a_02_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 90 01 08 2e 64 6c 6c 90 00 } //01 00 
		$a_02_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 69 76 65 72 73 5c 90 01 08 2e 73 79 73 90 00 } //01 00 
		$a_02_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 90 01 08 2e 64 72 76 90 00 } //01 00 
		$a_02_6 = {80 a5 d4 fe ff ff 00 6a 3f 59 33 c0 8d bd d5 fe ff ff f3 ab 66 ab aa 68 c8 00 00 00 8d 85 d4 fe ff ff 50 ff 15 90 01 04 68 90 01 04 8d 85 d4 fe ff ff 50 ff 15 90 01 04 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 85 d4 fe ff ff 50 ff 15 90 01 04 89 45 fc 83 7d fc ff 75 0e ff 75 d4 ff 15 90 01 04 6a 01 58 eb 4d 83 65 dc 00 33 c0 8d 7d e0 ab ab ab ab ab 8d 45 ec 50 8d 45 e4 50 8d 45 dc 50 ff 75 fc ff 15 90 01 04 8d 45 ec 50 8d 45 e4 50 8d 45 dc 50 ff 75 d4 ff 15 90 01 04 ff 75 fc ff 15 90 01 04 ff 75 d4 ff 15 90 01 04 6a 01 58 5f 5e 5b c9 c2 0c 00 90 00 } //01 00 
		$a_02_7 = {80 a5 ec fe ff ff 00 6a 3f 59 33 c0 8d bd ed fe ff ff f3 ab 66 ab aa 68 ff 00 00 00 8d 85 ec fe ff ff 50 ff 15 90 01 04 68 50 30 40 00 8d 85 ec fe ff ff 50 ff 15 90 01 04 8d 85 ec fe ff ff 50 8b 45 08 05 dc 04 00 00 50 ff 15 90 01 04 8b 45 08 05 6c 02 00 00 50 8b 45 08 05 dc 04 00 00 50 ff 15 90 01 04 68 48 30 40 00 8b 45 08 05 dc 04 00 00 50 ff 15 90 01 04 8d 85 ec fe ff ff 50 8b 45 08 05 dc 06 00 00 50 ff 15 90 01 04 8b 45 08 05 6c 02 00 00 50 8b 45 08 05 dc 06 00 00 50 ff 15 90 01 04 68 40 30 40 00 8b 45 08 05 dc 06 00 00 50 ff 15 90 01 04 8d 85 ec fe ff ff 50 8b 45 08 05 dc 05 00 00 50 ff 15 90 01 04 68 34 30 40 00 8b 45 08 05 dc 05 00 00 50 ff 15 90 01 04 8b 45 08 05 6c 02 00 00 50 8b 45 08 05 dc 05 00 00 50 ff 15 90 00 } //01 00 
		$a_00_8 = {6a 2c 8d 85 c0 fe ff ff 50 e8 c7 04 00 00 59 59 8b 45 08 8b 8d c8 fe ff ff 89 08 8b 45 08 8b 8d cc fe ff ff 89 48 04 8b 45 08 8b 8d d0 fe ff ff 89 48 08 8b 45 08 8b 8d d4 fe ff ff 89 48 0c 8b 45 08 8b 8d d8 fe ff ff 89 48 10 0f b7 85 e4 fe ff ff 0f b7 8d de fe ff ff 03 c1 0f b7 8d dc fe ff ff 03 c1 0f b7 8d e0 fe ff ff 03 c1 0f b7 8d e8 fe ff ff 03 c1 0f b7 8d e6 fe ff ff 03 c1 0f b7 8d e2 fe ff ff 03 c1 89 45 f0 6a 02 6a 00 8b 45 f0 83 c0 2c 33 c9 2b c8 } //00 00 
	condition:
		any of ($a_*)
 
}