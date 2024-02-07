
rule Trojan_Win32_Gaboc_A{
	meta:
		description = "Trojan:Win32/Gaboc.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 01 58 66 89 7d ea 66 89 45 e8 66 89 45 e6 66 89 45 e4 66 89 45 e2 66 89 45 de 8d 45 dc 50 66 c7 45 dc c6 07 ff d6 bf 10 27 00 00 57 ff 15 90 01 04 83 7d f8 00 75 0a 90 00 } //01 00 
		$a_03_1 = {6a 1c 5e a1 90 01 04 68 90 01 04 ff 34 06 e8 90 01 04 59 85 c0 59 74 61 83 c6 04 81 fe 94 00 00 00 7c dd 90 00 } //01 00 
		$a_03_2 = {74 25 57 6a 05 56 ff 15 90 01 04 6a ff 8b f8 ff 74 24 10 e8 90 01 04 59 50 6a 00 ff d7 90 00 } //01 00 
		$a_01_3 = {25 73 25 73 26 6d 61 63 68 69 6e 65 6e 61 6d 65 3d 25 73 00 } //00 00  猥猥洦捡楨敮慮敭┽s
	condition:
		any of ($a_*)
 
}