
rule Trojan_Win32_Dantmil_A{
	meta:
		description = "Trojan:Win32/Dantmil.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 b5 28 ff ff ff 89 b5 20 ff ff ff 8d 45 90 01 01 89 85 d4 fe ff ff c7 85 cc fe ff ff 08 40 00 00 8d 90 00 } //02 00 
		$a_01_1 = {66 8b f0 8d 4d b0 51 8d 55 a0 52 8d 45 90 50 ff d7 50 8d 8d 70 ff ff ff 51 8d 95 60 ff ff ff 52 } //02 00 
		$a_01_2 = {66 83 39 01 75 15 8b 71 14 8b 41 10 f7 de 3b f0 72 05 ff d7 8b 4d e4 } //01 00 
		$a_00_3 = {44 00 30 00 35 00 36 00 34 00 45 00 46 00 34 00 37 00 34 00 43 00 46 00 39 00 32 00 31 00 44 00 33 00 41 00 34 00 36 00 32 00 46 00 42 00 38 00 } //00 00 
	condition:
		any of ($a_*)
 
}