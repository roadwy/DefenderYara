
rule TrojanDownloader_Win32_Upatre_H{
	meta:
		description = "TrojanDownloader:Win32/Upatre.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 00 65 00 73 00 2f 00 68 00 74 00 6d 00 6c 00 2f 00 2a 00 78 00 65 00 } //01 00 
		$a_01_1 = {68 00 74 00 62 00 6b 00 67 00 72 00 6e 00 64 00 } //01 00 
		$a_01_2 = {8b 45 b4 ff e0 } //00 00 
		$a_00_3 = {78 a1 } //01 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Upatre_H_2{
	meta:
		description = "TrojanDownloader:Win32/Upatre.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {a3 04 d9 40 00 66 c7 85 2c ff ff ff 6b 00 8a 8d 34 ff ff ff 88 8d 4d ff ff ff c6 45 a8 65 66 c7 85 2e ff ff ff 65 00 c6 45 ae 45 8a 95 2e ff ff ff 88 95 52 ff ff ff 66 c7 85 3a ff ff ff 32 00 } //01 00 
		$a_01_1 = {c6 85 4c ff ff ff 47 c6 85 4d ff ff ff 0d c6 85 4e ff ff ff 74 c6 85 4f ff ff ff 46 c6 85 50 ff ff ff 69 c6 85 51 ff ff ff 6c c6 85 52 ff ff ff 70 c6 85 53 ff ff ff 41 c6 85 54 ff ff ff 74 c6 85 55 ff ff ff 74 c6 85 56 ff ff ff 72 } //01 00 
		$a_03_2 = {ff ff ff 6b 8a 8d 90 01 01 ff ff ff 88 8d 90 01 01 ff ff ff c6 45 a8 65 90 01 03 ff ff ff 65 c6 45 ae 45 8a 95 90 01 01 ff ff ff 88 95 90 01 01 ff ff ff 90 01 03 ff ff ff 32 90 00 } //01 00 
		$a_03_3 = {c6 45 a8 65 8a 95 90 01 01 ff ff ff 88 95 90 01 01 ff ff ff 90 01 03 2e ff ff ff 65 00 c6 45 ae 45 8a 85 90 01 01 ff ff ff 88 85 90 01 01 ff ff ff 90 00 } //01 00 
		$a_03_4 = {c6 45 bc 65 8a 95 90 01 01 ff ff ff 88 95 90 01 01 ff ff ff 90 01 04 ff ff ff 65 00 c6 45 90 01 01 45 8a 85 90 01 01 ff ff ff 88 85 90 01 01 ff ff ff 90 00 } //01 00 
		$a_03_5 = {c6 45 bc 65 c6 85 79 ff ff ff 65 c6 45 c2 45 c6 85 7e ff ff ff 65 68 90 01 02 40 00 ff 15 90 00 } //01 00 
		$a_01_6 = {c6 45 86 70 c6 45 87 41 c6 45 88 74 c6 45 89 74 c6 45 8a 72 c6 45 8b 69 c6 45 8c 62 c6 45 8d 75 c6 45 8e 74 c6 45 8f 65 c6 45 90 73 } //00 00 
	condition:
		any of ($a_*)
 
}