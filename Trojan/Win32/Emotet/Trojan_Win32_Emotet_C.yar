
rule Trojan_Win32_Emotet_C{
	meta:
		description = "Trojan:Win32/Emotet.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 54 87 f1 51 90 01 01 ce e8 90 01 02 ff ff 89 fa b8 02 00 00 00 52 d1 e0 89 c1 89 d8 90 00 } //01 00 
		$a_00_1 = {6d 00 61 00 6a 00 6f 00 72 00 63 00 68 00 65 00 6c 00 73 00 65 00 61 00 31 00 61 00 6e 00 64 00 46 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 73 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //01 00  majorchelsea1andFrequestsapplication
		$a_00_2 = {7a 31 65 2e 62 6d 61 69 32 39 38 52 73 42 53 32 } //01 00  z1e.bmai298RsBS2
		$a_00_3 = {62 00 6f 00 66 00 38 00 30 00 66 00 54 00 72 00 69 00 6e 00 69 00 74 00 79 00 49 00 74 00 } //00 00  bof80fTrinityIt
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_C_2{
	meta:
		description = "Trojan:Win32/Emotet.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {f7 e6 8b c2 c1 e8 05 33 d2 bf 19 00 00 00 f7 f7 8b c6 c1 e8 05 c1 e9 03 83 c2 61 52 33 d2 } //01 00 
		$a_03_1 = {53 6a 05 6a 02 53 53 68 00 00 00 40 56 ff 15 90 01 04 8b f8 83 ff ff 90 00 } //02 00 
		$a_00_2 = {25 00 73 00 5c 00 6d 00 73 00 25 00 75 00 2e 00 62 00 61 00 74 00 00 00 } //01 00 
		$a_00_3 = {25 00 73 00 5c 00 49 00 64 00 65 00 6e 00 74 00 69 00 74 00 69 00 65 00 73 00 5c 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 2e 00 65 00 78 00 65 00 00 00 } //00 00 
		$a_00_4 = {78 b2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_C_3{
	meta:
		description = "Trojan:Win32/Emotet.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {76 62 61 72 76 75 6c 6e 65 72 61 62 69 6c 69 74 69 65 73 4a 61 7a 61 79 65 72 69 } //01 00  vbarvulnerabilitiesJazayeri
		$a_00_1 = {5a 00 62 00 75 00 74 00 54 00 6f 00 72 00 72 00 65 00 6e 00 74 00 46 00 72 00 65 00 61 00 6b 00 41 00 70 00 72 00 69 00 6c 00 43 00 49 00 41 00 } //01 00  ZbutTorrentFreakAprilCIA
		$a_00_2 = {53 00 31 00 36 00 38 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 } //01 00  S168downloaded
		$a_03_3 = {55 54 89 e8 83 c0 10 31 c9 89 da 90 01 05 00 09 d0 83 c1 04 83 f8 00 74 21 5a 01 ca 90 01 05 00 90 01 05 00 83 f9 00 90 01 04 ff ff 85 c0 74 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_C_4{
	meta:
		description = "Trojan:Win32/Emotet.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 78 10 0b 00 04 3d 75 09 33 c9 66 3b 48 18 0f 95 c3 b9 } //01 00 
		$a_01_1 = {8a 08 80 f9 2f 74 0a 80 f9 5c 74 05 80 f9 3a 75 01 } //01 00 
		$a_03_2 = {2f 69 6e 2f 67 6f 2e 70 68 70 00 90 02 10 2e 70 77 00 90 00 } //01 00 
		$a_03_3 = {25 73 3f 69 64 3d 25 73 90 02 08 50 4f 53 54 90 00 } //01 00 
		$a_01_4 = {5c 43 6c 69 65 6e 74 73 5c 4d 61 69 6c 5c 00 00 44 4c 4c 50 61 74 68 45 78 00 } //01 00 
		$a_01_5 = {7b 5c 2a 5c 68 74 6d 6c 74 61 67 00 5c 2a 5c 68 74 6d 6c 74 61 67 00 } //01 00 
		$a_01_6 = {5c 73 70 61 6d 5c 65 78 70 6f 72 74 5f 65 6d 61 69 6c 5f 6f 75 74 6c 6f 6f 6b 5c } //01 00  \spam\export_email_outlook\
		$a_01_7 = {5c 6d 61 69 6c 64 65 6d 6f 2d 70 6f 69 73 6b 20 65 6d 61 69 6c 20 76 20 6f 75 74 6c 6f 6f 6b 5c } //01 00  \maildemo-poisk email v outlook\
		$a_03_8 = {2f 6d 33 2f 64 61 74 61 2e 70 68 70 00 90 02 10 2e 90 03 02 05 72 75 63 6f 2e 75 61 00 90 00 } //01 00 
		$a_01_9 = {2f 69 6e 70 75 74 2f 69 6e 2f 69 6e 64 65 78 2e 70 68 70 } //01 00  /input/in/index.php
		$a_01_10 = {2f 69 6e 70 75 74 2f 69 6e 2f 4e 77 68 33 37 71 41 52 2e 70 68 70 } //00 00  /input/in/Nwh37qAR.php
		$a_00_11 = {80 10 00 } //00 e3 
	condition:
		any of ($a_*)
 
}