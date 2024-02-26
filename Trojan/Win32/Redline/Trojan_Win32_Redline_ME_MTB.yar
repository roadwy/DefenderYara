
rule Trojan_Win32_Redline_ME_MTB{
	meta:
		description = "Trojan:Win32/Redline.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {89 55 ec 8b d7 d3 ea c7 05 90 01 08 03 55 d8 8b 45 ec 31 45 fc 33 55 fc 89 55 ec 8b 45 ec 83 45 f8 64 29 45 f8 83 6d f8 64 83 3d 60 41 84 00 0c 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_ME_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {c1 e2 06 0b ca 88 8d 90 01 04 0f b6 85 90 01 04 03 85 90 01 04 88 85 90 01 04 0f b6 8d 90 01 04 f7 d1 88 8d 90 01 04 0f b6 95 90 01 04 33 95 90 01 04 88 95 90 01 04 8b 85 90 01 04 8a 8d 90 01 04 88 8c 05 70 ff ff ff e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_ME_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {c1 e0 03 0b d0 88 95 90 01 04 0f b6 8d 90 01 04 f7 d1 88 8d 90 01 04 0f b6 95 90 01 04 83 ea 58 88 95 90 01 04 0f b6 85 90 01 04 c1 f8 03 0f b6 8d 90 01 04 c1 e1 05 0b c1 88 85 90 01 04 8b 95 90 01 04 8a 85 90 01 04 88 84 15 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_ME_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 61 6c 20 68 6f 63 69 68 61 6d 61 20 68 69 6e 6f 20 6a 69 6e 61 71 75 } //01 00  sal hocihama hino jinaqu
		$a_01_1 = {74 69 71 75 6f 64 20 6b 69 64 6f } //01 00  tiquod kido
		$a_01_2 = {6b 6f 6e 61 66 20 73 61 71 75 6f 70 65 20 67 69 67 20 70 6f 62 65 6a 65 } //01 00  konaf saquope gig pobeje
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_4 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetTickCount
		$a_01_5 = {47 65 74 43 75 72 73 6f 72 49 6e 66 6f } //01 00  GetCursorInfo
		$a_01_6 = {68 00 6f 00 74 00 6b 00 65 00 79 00 } //00 00  hotkey
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_ME_MTB_5{
	meta:
		description = "Trojan:Win32/Redline.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 44 24 60 81 6c 24 38 27 ea 21 11 81 6c 24 28 6b 07 bb 7c 81 44 24 28 4a ed 6f 20 81 6c 24 38 17 ff 9e 54 b8 ce 53 c0 1c f7 64 24 40 8b 44 24 40 81 6c 24 7c 4a e2 62 25 81 6c 24 20 9c 3b df 75 81 6c 24 38 00 ac 9a 59 b8 9a 7b f6 4a f7 64 24 20 8b 44 24 20 81 6c 24 28 b5 d6 af 6e 81 44 24 68 1b ee 2f 65 b8 22 cf 72 1e } //01 00 
		$a_01_1 = {55 6e 68 61 6e 64 6c 65 64 45 78 63 65 70 74 69 6f 6e 46 69 6c 74 65 72 } //01 00  UnhandledExceptionFilter
		$a_01_2 = {43 72 65 61 74 65 4d 61 69 6c 73 6c 6f 74 57 } //01 00  CreateMailslotW
		$a_01_3 = {47 65 74 43 50 49 6e 66 6f } //00 00  GetCPInfo
	condition:
		any of ($a_*)
 
}