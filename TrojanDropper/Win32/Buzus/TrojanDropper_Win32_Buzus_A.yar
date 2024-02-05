
rule TrojanDropper_Win32_Buzus_A{
	meta:
		description = "TrojanDropper:Win32/Buzus.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 ec ba 00 2d 40 00 e8 dc f0 ff ff 75 07 33 c0 e8 a3 ee ff ff e8 32 f8 ff ff 3c 01 75 07 33 c0 e8 93 ee ff ff e8 7a f9 ff ff e8 5d fc ff ff 90 01 02 5a 59 59 64 89 10 68 f0 2c 40 00 8d 45 ec e8 8c ee ff ff c3 90 00 } //01 00 
		$a_01_1 = {53 56 8b f0 6a 0a 52 a1 6c 46 40 00 50 e8 56 fd ff ff 8b d8 53 a1 6c 46 40 00 50 e8 70 fd ff ff 89 06 53 a1 6c 46 40 00 50 e8 52 fd ff ff 8b d8 53 e8 52 fd ff ff 8b f0 85 f6 74 06 53 e8 2e fd ff ff 8b c6 5e 5b c3 } //00 00 
	condition:
		any of ($a_*)
 
}