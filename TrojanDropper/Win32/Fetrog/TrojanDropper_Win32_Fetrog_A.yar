
rule TrojanDropper_Win32_Fetrog_A{
	meta:
		description = "TrojanDropper:Win32/Fetrog.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {69 d2 6d a9 33 60 b8 8f 3b 48 dd 2b c2 8b d0 c1 e8 08 30 01 } //01 00 
		$a_03_1 = {68 00 24 89 85 51 c7 44 24 90 01 01 00 00 00 00 ff 15 90 01 04 85 c0 74 10 81 7c 24 90 01 01 00 10 00 00 75 06 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 32 2d 03 80 5c 25 } //00 00 
	condition:
		any of ($a_*)
 
}