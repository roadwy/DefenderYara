
rule Trojan_Win32_Necurs_gen_A{
	meta:
		description = "Trojan:Win32/Necurs.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 85 fc fc ff ff 72 c6 85 fd fc ff ff 77 c6 85 fe fc ff ff 63 c6 85 ff fc ff ff 00 } //01 00 
		$a_01_1 = {ff d2 33 c0 b0 04 03 e0 } //01 00 
		$a_01_2 = {3d 35 8e f8 1f 6a 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Necurs_gen_A_2{
	meta:
		description = "Trojan:Win32/Necurs.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4b 3c 03 cb 8b 81 a0 00 00 00 8b 91 a4 00 00 00 89 55 f8 85 c0 74 63 } //01 00 
		$a_01_1 = {8b 41 3c 6a 00 ff 74 08 50 51 e8 02 ff ff ff 83 c4 0c 5d c3 } //01 00 
		$a_03_2 = {35 de c0 ad de 89 45 90 01 01 ff 15 90 01 04 33 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Necurs_gen_A_3{
	meta:
		description = "Trojan:Win32/Necurs.gen!A,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 00 3f 00 3f 00 5c 00 4e 00 74 00 53 00 65 00 63 00 75 00 72 00 65 00 53 00 79 00 73 00 00 00 } //0a 00 
		$a_01_1 = {5c 5c 2e 5c 4e 74 53 65 63 75 72 65 53 79 73 00 } //0a 00  屜尮瑎敓畣敲祓s
		$a_01_2 = {44 00 42 00 35 00 00 00 44 00 42 00 36 00 00 00 } //0a 00 
		$a_01_3 = {44 00 42 00 31 00 00 00 6c 73 61 73 73 2e 65 78 65 00 } //01 00 
		$a_01_4 = {62 63 64 65 64 69 74 2e 65 78 65 20 2d 73 65 74 20 54 45 53 54 53 49 47 4e 49 4e 47 20 4f 4e 00 } //01 00 
		$a_01_5 = {32 00 30 00 31 00 30 00 31 00 00 00 00 00 00 00 4f 00 62 00 52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 43 00 61 00 6c 00 6c 00 62 00 61 00 63 00 6b 00 73 00 00 00 } //01 00 
		$a_01_6 = {42 00 6f 00 6f 00 74 00 20 00 42 00 75 00 73 00 20 00 45 00 78 00 74 00 65 00 6e 00 64 00 65 00 72 00 00 00 } //01 00 
		$a_01_7 = {57 00 69 00 6e 00 44 00 65 00 66 00 65 00 6e 00 64 00 00 00 } //01 00 
		$a_01_8 = {4b 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 48 00 61 00 63 00 6b 00 65 00 72 00 00 00 } //00 00 
		$a_01_9 = {00 78 42 } //00 00 
	condition:
		any of ($a_*)
 
}