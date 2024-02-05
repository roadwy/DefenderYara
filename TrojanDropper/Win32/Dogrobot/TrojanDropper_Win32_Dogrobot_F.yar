
rule TrojanDropper_Win32_Dogrobot_F{
	meta:
		description = "TrojanDropper:Win32/Dogrobot.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff 75 e4 6a 00 ff 15 90 01 02 40 00 85 c0 74 90 01 01 90 90 8b 45 ec 03 45 d8 0f b6 00 83 c0 90 01 01 88 45 fc 68 c3 d1 3f 0f 6a 01 e8 90 01 04 89 45 d0 6a 00 8d 45 e0 50 6a 01 90 00 } //01 00 
		$a_03_1 = {72 65 63 79 63 6c 65 2e 7b 90 01 08 2d 90 01 04 2d 90 01 04 2d 90 01 04 2d 90 01 0c 7d 5c 6b 61 76 33 32 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}