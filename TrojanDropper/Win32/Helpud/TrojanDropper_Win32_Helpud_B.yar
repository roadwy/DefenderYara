
rule TrojanDropper_Win32_Helpud_B{
	meta:
		description = "TrojanDropper:Win32/Helpud.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 78 05 90 75 19 80 78 06 f0 75 13 80 78 07 b9 75 0d 80 78 08 43 75 07 } //01 00 
		$a_03_1 = {66 81 00 a5 8c 8b 55 90 01 01 41 40 d1 ea 40 3b ca 72 ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}