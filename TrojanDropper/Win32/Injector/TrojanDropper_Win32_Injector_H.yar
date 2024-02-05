
rule TrojanDropper_Win32_Injector_H{
	meta:
		description = "TrojanDropper:Win32/Injector.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 51 c7 84 24 90 01 01 00 00 00 02 00 01 00 ff 15 90 00 } //01 00 
		$a_03_1 = {8b 73 3c 03 f3 81 3e 50 45 00 00 0f 85 90 01 02 00 00 83 c6 04 89 74 24 28 83 90 01 01 14 90 00 } //01 00 
		$a_03_2 = {8b 44 24 28 33 90 01 01 83 90 01 01 28 45 66 8b 50 02 3b 90 01 01 7e ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}