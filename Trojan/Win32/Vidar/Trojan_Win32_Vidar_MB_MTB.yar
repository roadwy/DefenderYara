
rule Trojan_Win32_Vidar_MB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 8d 50 01 8b 45 ec 01 d0 0f b6 84 05 1e 8f ff ff 88 85 2f bb ff ff 8b 45 f0 8d 50 01 8b 45 ec 01 c2 8b 45 f4 83 e8 01 2b 45 ec 0f b6 84 05 1e 8f ff ff 88 84 15 1e 8f ff ff 8b 45 f4 83 e8 01 2b 45 ec 0f b6 95 2f bb ff ff 88 94 05 1e 8f ff ff 83 45 ec 01 eb } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Vidar_MB_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {73 2e e0 65 9c cc 87 bf a4 fa 10 10 61 6c a1 01 a3 3d a3 ab 23 f9 15 47 10 e5 90 4e 08 24 c2 cc 20 75 3a 4d d9 c7 8c f9 68 50 40 f6 bb fd 25 46 } //05 00 
		$a_01_1 = {6b 71 4a d1 2b db 23 90 30 d5 65 cb f0 2a b6 ad 70 4b 27 c2 60 36 13 10 8d 35 a1 8b 20 4c be 7e e8 32 b7 9c 1b fc 29 4f 9a 28 85 0f 28 01 1e bd } //05 00 
		$a_01_2 = {e0 00 02 01 0b 01 0a 00 00 ee 03 00 00 e8 } //01 00 
		$a_01_3 = {2e 74 68 65 6d 69 64 61 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Vidar_MB_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 04 00 00 14 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 85 10 fc ff ff 33 d2 f7 f1 8b 85 0c fc ff ff 8a 0c 02 8b 85 10 fc ff ff 8b 95 08 fc ff ff 03 c3 32 0c 02 88 08 8d 85 14 fc ff ff 50 } //05 00 
		$a_01_1 = {73 64 66 6b 6a 6e 73 64 66 6b 6a 6c 6e 6b 20 6a 68 73 64 62 66 6a 73 68 64 } //14 00 
		$a_01_2 = {8b c8 8b 85 28 f8 ff ff 33 d2 f7 f1 8b 85 20 f8 ff ff 8a 0c 02 8b 85 18 f8 ff ff 8b 95 1c f8 ff ff 32 0c 02 88 08 8d 85 2c f8 ff ff 50 8d 85 14 fc ff ff 50 } //05 00 
		$a_01_3 = {73 6b 6a 64 33 38 37 32 36 32 38 37 33 34 36 77 75 79 67 32 33 37 36 34 74 32 67 66 37 36 66 67 79 74 72 } //00 00 
	condition:
		any of ($a_*)
 
}