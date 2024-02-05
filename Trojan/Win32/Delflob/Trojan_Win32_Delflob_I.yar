
rule Trojan_Win32_Delflob_I{
	meta:
		description = "Trojan:Win32/Delflob.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {c7 45 e8 01 00 00 00 8d 45 90 01 01 8b 55 fc 8b 4d e8 8a 54 0a ff 8a 4d fb 32 d1 e8 90 01 03 ff 8b 55 90 01 01 8d 45 f0 e8 90 01 03 ff ff 45 e8 ff 4d 90 01 01 75 d6 90 00 } //01 00 
		$a_02_1 = {c7 45 e8 01 00 00 00 8d 85 90 01 02 ff ff 8b 55 fc 8b 4d e8 8a 54 0a ff 8a 4d fb 32 d1 e8 90 01 03 ff 8b 95 90 01 02 ff ff 8d 45 f0 e8 90 01 03 ff ff 45 e8 ff 4d 90 01 01 75 d0 90 00 } //01 00 
		$a_02_2 = {c7 45 e8 01 00 00 00 8d 85 90 01 02 ff ff 8b 55 fc 8b 4d e8 8a 54 0a ff 8a 4d fb 32 d1 e8 90 01 03 ff 8b 95 90 01 02 ff ff 8d 45 f0 e8 90 01 03 ff ff 45 e8 ff 8d 90 01 02 ff ff 75 cd 90 00 } //01 00 
		$a_02_3 = {c7 45 e8 01 00 00 00 8d 45 90 01 01 8a 55 fb 8b 4d fc 8b 5d e8 8a 4c 19 ff 32 d1 e8 90 01 03 ff 8b 55 90 01 01 8d 45 f0 e8 90 01 03 ff ff 45 e8 ff 4d 90 01 01 75 d6 90 00 } //01 00 
		$a_03_4 = {c7 45 e8 01 00 00 00 8d 85 90 01 02 ff ff 8b 55 e8 8b 4d fc 4a 85 c9 74 05 3b 51 fc 72 05 e8 90 01 02 ff ff 42 8a 54 11 ff 8a 4d fb 32 d1 e8 90 01 02 ff ff 8b 95 90 01 02 ff ff 8d 45 f0 e8 90 01 02 ff ff ff 45 90 01 01 ff 4d 90 01 01 75 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}