
rule Trojan_Win32_Redosdru_C{
	meta:
		description = "Trojan:Win32/Redosdru.C,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 54 24 04 8a 1c 11 80 c3 90 01 01 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 90 01 01 88 1c 11 41 3b c8 7c e1 90 00 } //05 00 
		$a_01_1 = {6a 02 6a 00 68 00 fc ff ff 56 ff 15 } //01 00 
		$a_02_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d 90 02 08 2e 65 78 65 90 00 } //01 00 
		$a_00_3 = {71 6d 67 72 2e 64 6c 6c 00 5c 44 72 69 76 65 72 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redosdru_C_2{
	meta:
		description = "Trojan:Win32/Redosdru.C,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 08 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 54 24 04 8a 1c 11 80 c3 90 01 01 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 90 01 01 88 1c 11 41 3b c8 7c e1 90 00 } //05 00 
		$a_01_1 = {6a 02 6a 00 68 00 fc ff ff 56 ff 15 } //02 00 
		$a_03_2 = {6a 7c 53 e8 90 01 02 00 00 8b f0 83 c4 08 85 f6 0f 84 90 01 02 00 00 83 c3 06 c6 06 00 90 00 } //01 00 
		$a_01_3 = {3d 00 00 20 03 73 0d 6a 02 6a 00 6a 00 53 ff 15 } //01 00 
		$a_03_4 = {8a 14 01 80 f2 90 01 01 88 10 40 4d 75 f4 90 00 } //01 00 
		$a_01_5 = {25 73 5c 25 64 5f 72 65 73 2e 74 6d 70 } //01 00  %s\%d_res.tmp
		$a_01_6 = {47 68 30 73 74 20 55 70 64 61 74 65 } //01 00  Gh0st Update
		$a_01_7 = {25 73 5c 25 73 65 78 2e 64 6c 6c } //00 00  %s\%sex.dll
	condition:
		any of ($a_*)
 
}