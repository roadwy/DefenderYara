
rule Trojan_Win32_Foosace_C_dha{
	meta:
		description = "Trojan:Win32/Foosace.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 2e 32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 } //01 00  %.2x%.2x%.2x%.2x
		$a_01_1 = {25 73 2f 63 67 69 2d 62 69 6e 2f 25 73 2e 63 67 69 3f 25 73 00 } //01 00 
		$a_01_2 = {69 6e 73 3a 25 2e 38 78 00 } //01 00 
		$a_01_3 = {49 6e 69 74 31 00 } //00 00  湉瑩1
		$a_00_4 = {78 39 01 } //00 08 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Foosace_C_dha_2{
	meta:
		description = "Trojan:Win32/Foosace.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 06 00 "
		
	strings :
		$a_00_0 = {8d 41 01 89 45 14 8a 44 0e fe 02 c3 8d 51 fe 02 c2 c0 e0 04 8d 79 ff 83 e7 07 32 04 37 8b 7d 14 02 da 83 e7 07 32 1c 37 8b d1 83 e2 07 22 1c 32 8b 55 f8 f6 eb 30 04 0a 8b 4d 14 8d 41 fe 83 f8 08 } //02 00 
		$a_01_1 = {41 70 70 6c 69 63 61 74 65 } //02 00  Applicate
		$a_01_2 = {63 6f 72 65 73 68 65 6c 6c } //04 00  coreshell
		$a_03_3 = {31 db 89 55 98 89 da f7 f6 05 02 00 00 00 0f af ff 81 c7 05 00 00 00 39 f8 0f 84 62 07 00 00 8b 45 98 89 45 94 e9 55 00 00 00 a1 90 01 04 8b 0d 90 01 04 0f af c0 69 c0 07 00 00 00 2d 01 00 00 00 0f af c9 39 c8 0f 84 82 07 00 00 a1 90 01 04 8b 0d 90 01 04 0f af c0 69 c0 07 00 00 00 2d 01 00 00 00 0f af c9 39 c8 0f 84 5e 07 00 00 b8 00 00 00 00 89 45 94 e9 00 00 00 00 8b 45 94 8b 4d c4 89 01 b8 02 00 00 00 8b 0d 90 01 04 8b 15 90 01 04 0f af c9 81 c1 01 00 00 00 31 f6 89 55 90 90 89 f2 f7 f1 05 02 00 00 00 8b 4d 90 90 0f af c9 81 c1 05 00 00 00 39 c8 90 00 } //02 00 
		$a_80_4 = {5c 63 68 6b 64 62 67 2e 6c 6f 67 } //\chkdbg.log  00 00 
		$a_00_5 = {5d 04 00 00 55 38 } //03 80 
	condition:
		any of ($a_*)
 
}