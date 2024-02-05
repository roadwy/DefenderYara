
rule TrojanDropper_Win32_Injector_I{
	meta:
		description = "TrojanDropper:Win32/Injector.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 00 0c 60 8b 4d 90 01 01 03 c8 89 4d 90 01 01 8b 45 90 01 01 d1 e0 89 45 90 00 } //02 00 
		$a_03_1 = {f7 75 14 8b 45 0c 0f b6 04 90 01 01 03 90 01 01 99 b9 00 90 01 02 00 f7 f9 89 55 90 00 } //01 00 
		$a_03_2 = {ff 6b c6 85 90 01 02 ff ff 43 c6 85 90 01 02 ff ff 5a c6 85 90 01 02 ff ff 56 c6 85 90 01 02 ff ff 47 90 00 } //01 00 
		$a_03_3 = {ff 70 50 8b 85 90 01 02 ff ff ff 70 34 ff 75 90 01 01 ff 95 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}