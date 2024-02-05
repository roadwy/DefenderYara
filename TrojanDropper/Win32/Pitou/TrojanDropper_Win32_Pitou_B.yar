
rule TrojanDropper_Win32_Pitou_B{
	meta:
		description = "TrojanDropper:Win32/Pitou.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 7c 7a bd e4 e8 90 01 04 8b 00 ff d0 90 00 } //01 00 
		$a_01_1 = {33 d1 8b 45 0c 88 10 8b 4d 0c 83 c1 01 89 4d 0c 8b 55 f4 83 c2 01 89 55 f4 8b 45 f8 03 45 f0 0f b6 08 d1 e1 } //00 00 
	condition:
		any of ($a_*)
 
}