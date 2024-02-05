
rule TrojanDropper_Win32_Gamarue_H{
	meta:
		description = "TrojanDropper:Win32/Gamarue.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 31 89 45 90 01 01 8b 45 90 01 01 33 d2 f7 f7 66 8b 04 55 90 01 04 66 89 04 71 85 f6 75 90 00 } //01 00 
		$a_03_1 = {8a 0c 30 80 e9 90 01 01 32 ca ff 44 24 90 01 01 88 0c 30 39 7c 24 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}