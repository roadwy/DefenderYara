
rule Trojan_Win32_Alureon_BG{
	meta:
		description = "Trojan:Win32/Alureon.BG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 44 49 42 47 68 32 4c 44 54 } //01 00  hDIBGh2LDT
		$a_01_1 = {80 38 e9 74 04 33 c0 eb 07 8b 48 01 8d 44 01 05 } //01 00 
		$a_01_2 = {59 75 15 81 c6 20 02 00 00 47 8b c6 83 3e 00 75 e4 } //01 00 
		$a_01_3 = {8a d1 02 54 24 0c 30 14 01 41 3b 4c 24 08 72 f0 } //01 00 
		$a_01_4 = {46 52 32 34 33 35 33 32 } //01 00  FR243532
		$a_03_5 = {6a 01 6a 09 68 90 01 04 8b c6 e8 90 01 02 00 00 85 c0 74 19 57 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}