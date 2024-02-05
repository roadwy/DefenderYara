
rule TrojanDropper_Win32_Sirefef_A{
	meta:
		description = "TrojanDropper:Win32/Sirefef.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 75 fc 6a 40 59 8d bd dc fe ff ff 8d 85 dc fe ff ff f3 a5 50 8d b5 dc fd ff ff e8 90 01 04 8b 45 fc 6a 40 8b f0 8d bd dc fe ff ff 59 f3 a5 be ff 00 00 00 03 c6 8b 4d f8 0f b6 0c 01 8a 8c 0d dc fe ff ff 88 08 8b ce 4e 48 85 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Sirefef_A_2{
	meta:
		description = "TrojanDropper:Win32/Sirefef.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 39 4e 88 8c 05 90 01 02 ff ff 48 85 f6 77 eb 01 55 f8 ff 4d fc 6a 40 59 8d b5 90 01 02 ff ff f3 a5 75 d1 6a 0a 6a 66 90 00 } //01 00 
		$a_03_1 = {8b f8 85 ff 74 4e 6a 10 58 e8 90 01 02 00 00 8b f4 8d 47 60 50 6a 20 83 c6 f0 56 ff 15 90 01 02 40 00 56 6a 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Sirefef_A_3{
	meta:
		description = "TrojanDropper:Win32/Sirefef.A,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 75 fc 6a 40 59 8d bd dc fe ff ff 8d 85 dc fe ff ff f3 a5 50 8d b5 dc fd ff ff e8 90 01 04 8b 45 fc 6a 40 8b f0 8d bd dc fe ff ff 59 f3 a5 be ff 00 00 00 03 c6 8b 4d f8 0f b6 0c 01 8a 8c 0d dc fe ff ff 88 08 8b ce 4e 48 85 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Sirefef_A_4{
	meta:
		description = "TrojanDropper:Win32/Sirefef.A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 39 4e 88 8c 05 90 01 02 ff ff 48 85 f6 77 eb 01 55 f8 ff 4d fc 6a 40 59 8d b5 90 01 02 ff ff f3 a5 75 d1 6a 0a 6a 66 90 00 } //01 00 
		$a_03_1 = {8b f8 85 ff 74 4e 6a 10 58 e8 90 01 02 00 00 8b f4 8d 47 60 50 6a 20 83 c6 f0 56 ff 15 90 01 02 40 00 56 6a 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}