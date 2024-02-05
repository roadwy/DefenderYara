
rule Trojan_Win32_Small{
	meta:
		description = "Trojan:Win32/Small,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 fc a3 68 aa 40 00 c7 45 90 01 01 10 00 00 00 8d 45 90 01 01 50 8d 85 90 01 01 f9 ff ff 50 e8 90 01 01 dd ff ff 8d 85 90 01 01 f9 ff ff e8 90 00 } //01 00 
		$a_02_1 = {55 8b ec 81 c4 90 01 01 f8 ff ff 53 56 57 90 02 01 31 c0 50 b9 61 72 79 41 64 03 40 30 51 68 4c 69 62 72 78 0f 8b 40 0c 31 d2 8b 40 1c 8b 00 8b 40 08 eb 0d 8b 40 34 31 d2 8d 40 7c 31 d2 8b 40 3c b9 cf 6e 61 64 83 c1 7d 51 54 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Small_2{
	meta:
		description = "Trojan:Win32/Small,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 67 69 72 6c 72 61 63 65 72 2e 6d 65 2e 75 6b 2f 6c 61 6e 67 75 61 67 65 2f 6c 61 6e 67 5f 65 6e 67 6c 69 73 68 2f } //03 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 68 75 6d 6f 72 74 61 64 65 6c 61 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 } //02 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //02 00 
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00 
		$a_01_4 = {2e 73 63 72 } //01 00 
		$a_01_5 = {2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Small_3{
	meta:
		description = "Trojan:Win32/Small,SIGNATURE_TYPE_PEHSTR,0d 00 0b 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 64 65 6d 6f 2e 64 6f 6b 65 6f 73 2e 63 6f 6d 2f 63 6f 75 72 73 65 73 2f 45 52 49 43 2f 77 6f 72 6b 2f } //02 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 68 75 6d 6f 72 74 61 64 65 6c 61 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 } //02 00 
		$a_01_2 = {6c 69 6e 6b 20 64 61 20 70 61 67 75 69 6e 61 20 64 65 20 44 49 53 54 52 41 } //02 00 
		$a_01_3 = {4f 20 64 6f 20 49 6e 66 65 63 74 61 64 6f } //01 00 
		$a_01_4 = {2e 73 63 72 } //01 00 
		$a_01_5 = {2e 74 78 74 } //01 00 
		$a_01_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00 
		$a_01_7 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}