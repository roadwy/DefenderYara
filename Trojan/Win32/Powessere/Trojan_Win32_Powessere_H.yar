
rule Trojan_Win32_Powessere_H{
	meta:
		description = "Trojan:Win32/Powessere.H,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //01 00 
		$a_02_1 = {41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 22 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 22 00 29 00 3b 00 90 02 20 3d 00 22 00 90 02 20 22 00 3b 00 90 00 } //01 00 
		$a_02_2 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 22 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 90 02 20 5c 00 5c 00 90 02 20 22 00 29 00 3b 00 90 02 20 3d 00 22 00 90 02 20 22 00 3b 00 65 00 76 00 61 00 6c 00 28 00 90 02 20 29 00 3b 00 90 00 } //01 00 
		$a_02_3 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 22 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 90 02 20 5c 00 5c 00 90 02 20 22 00 29 00 3b 00 90 02 20 3d 00 22 00 90 02 20 22 00 3b 00 74 00 68 00 69 00 73 00 5b 00 27 00 65 00 76 00 27 00 2b 00 27 00 61 00 6c 00 27 00 5d 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Powessere_H_2{
	meta:
		description = "Trojan:Win32/Powessere.H,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //01 00 
		$a_00_1 = {61 00 62 00 6f 00 75 00 74 00 3a 00 3c 00 68 00 74 00 61 00 3a 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 3e 00 3c 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00 } //01 00 
		$a_00_2 = {72 00 65 00 73 00 69 00 7a 00 65 00 54 00 6f 00 28 00 31 00 2c 00 31 00 29 00 } //01 00 
		$a_00_3 = {65 00 76 00 61 00 6c 00 28 00 6e 00 65 00 77 00 20 00 41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 27 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 27 00 29 00 2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 27 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 4c 00 6f 00 77 00 5c 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 5c 00 } //01 00 
		$a_00_4 = {69 00 66 00 28 00 21 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 66 00 6c 00 61 00 67 00 29 00 63 00 6c 00 6f 00 73 00 65 00 28 00 29 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Powessere_H_3{
	meta:
		description = "Trojan:Win32/Powessere.H,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //01 00 
		$a_02_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 90 02 10 3d 00 27 00 27 00 3b 00 74 00 72 00 79 00 7b 00 74 00 68 00 72 00 6f 00 77 00 20 00 6e 00 65 00 77 00 20 00 45 00 72 00 72 00 6f 00 72 00 28 00 27 00 90 02 20 27 00 29 00 3b 00 7d 00 63 00 61 00 74 00 63 00 68 00 28 00 65 00 72 00 72 00 29 00 7b 00 90 02 10 3d 00 65 00 72 00 72 00 2e 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 3b 00 7d 00 90 00 } //01 00 
		$a_02_2 = {3d 00 6e 00 65 00 77 00 20 00 41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 27 00 57 00 90 02 30 29 00 3b 00 90 02 10 3d 00 27 00 27 00 3b 00 90 02 10 3d 00 27 00 5c 00 5c 00 90 02 20 5c 00 5c 00 90 02 20 27 00 3b 00 90 00 } //01 00 
		$a_02_3 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 27 00 48 00 4b 00 4c 00 4d 00 5c 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 57 00 6f 00 77 00 36 00 34 00 33 00 32 00 4e 00 6f 00 64 00 65 00 27 00 2b 00 90 02 10 29 00 3b 00 7d 00 63 00 61 00 74 00 63 00 68 00 28 00 90 02 10 29 00 7b 00 7d 00 74 00 72 00 79 00 7b 00 69 00 66 00 28 00 90 02 10 29 00 65 00 76 00 61 00 6c 00 28 00 90 02 10 29 00 3b 00 7d 00 63 00 61 00 74 00 63 00 68 00 28 00 90 02 10 29 00 7b 00 7d 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Powessere_H_4{
	meta:
		description = "Trojan:Win32/Powessere.H,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_02_1 = {41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 29 00 3b 00 90 02 20 3d 00 90 02 20 3b 00 90 00 } //01 00 
		$a_02_2 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 90 02 20 5c 00 5c 00 90 02 20 29 00 3b 00 90 02 20 3d 00 90 02 20 3b 00 74 00 68 00 69 00 73 00 5b 00 27 00 65 00 76 00 27 00 2b 00 27 00 61 00 6c 00 27 00 5d 00 90 00 } //01 00 
		$a_02_3 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 90 02 20 5c 00 5c 00 90 02 20 29 00 3b 00 90 02 20 3d 00 90 02 20 3b 00 65 00 76 00 61 00 6c 00 28 00 90 02 20 29 00 3b 00 90 00 } //01 00 
		$a_02_4 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 48 00 4b 00 4c 00 4d 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 57 00 6f 00 77 00 36 00 34 00 33 00 32 00 4e 00 6f 00 64 00 65 00 5c 00 5c 00 90 02 20 5c 00 5c 00 90 02 20 29 00 3b 00 90 02 20 3d 00 90 02 20 3b 00 65 00 76 00 61 00 6c 00 28 00 90 02 20 29 00 3b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}