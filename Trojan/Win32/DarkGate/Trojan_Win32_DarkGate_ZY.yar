
rule Trojan_Win32_DarkGate_ZY{
	meta:
		description = "Trojan:Win32/DarkGate.ZY,SIGNATURE_TYPE_PEHSTR_EXT,fffffff1 00 fffffff1 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_03_1 = {80 e1 3f c1 e1 02 8a 5d 90 01 01 80 e3 30 81 e3 ff 00 00 00 c1 eb 04 02 cb 90 00 } //64 00 
		$a_03_2 = {80 e1 0f c1 e1 04 8a 5d 90 01 01 80 e3 3c 81 e3 ff 00 00 00 c1 eb 02 02 cb 90 00 } //0a 00 
		$a_81_3 = {6d 65 69 6d 70 6f 72 74 61 75 6e 61 6d 69 65 72 64 61 73 69 64 65 73 63 69 66 72 61 73 6c 6f 73 6c 6f 67 73 } //0a 00  meimportaunamierdasidescifrasloslogs
		$a_81_4 = {70 75 65 72 74 6f 20 69 73 20 6e 6f 74 20 6e 75 6d 62 65 72 } //0a 00  puerto is not number
		$a_81_5 = {64 65 6c 69 6b 65 79 20 6e 6f 74 20 66 6f 75 6e 64 } //0a 00  delikey not found
		$a_81_6 = {2d 2d 5f 42 69 6e 64 65 72 5f 2d 2d } //00 00  --_Binder_--
		$a_00_7 = {5d 04 00 00 0c 62 06 80 5c 27 00 00 0d 62 06 80 00 00 01 00 08 00 11 00 ac 21 44 61 72 6b 47 61 74 65 2e 5a 59 21 73 6d 73 00 00 01 40 05 82 70 00 04 00 ce 09 00 00 ad f0 f7 ec 78 c0 00 00 7b 5d 04 00 00 0d 62 06 80 5c 24 00 00 0e 62 06 80 00 00 01 00 06 00 0e 00 84 a1 4d 69 72 61 69 2e 45 48 21 4d 54 42 00 00 01 40 05 82 42 00 04 00 8c fa 00 00 03 00 03 00 03 00 00 01 00 a3 00 48 83 fa 20 48 89 d1 49 89 fa fc 76 53 48 89 f8 48 f7 d8 48 83 e0 07 48 29 c1 48 91 f3 a4 48 89 c1 48 83 e9 20 78 35 66 66 90 66 66 90 66 66 90 48 83 e9 20 48 8b 06 48 8b 56 08 4c 8b 46 10 4c 8b 4e 18 48 89 07 48 89 57 08 4c 89 47 10 4c 89 4f 18 48 8d 76 20 48 8d 7f 20 79 d4 48 83 c1 20 f3 a4 4c 89 d0 c3 90 90 45 31 c0 48 85 ff 41 ba 01 } //00 00 
	condition:
		any of ($a_*)
 
}