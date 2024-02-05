
rule Ransom_Win32_Cerber_H{
	meta:
		description = "Ransom:Win32/Cerber.H,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 01 00 "
		
	strings :
		$a_80_0 = {45 6e 63 72 79 70 74 69 6e 67 20 64 6f 6e 65 2e 20 54 69 6d 65 20 6c 65 66 74 3a 20 25 64 6d 73 } //Encrypting done. Time left: %dms  01 00 
		$a_80_1 = {4e 65 74 77 6f 72 6b 20 73 65 61 72 63 68 69 6e 67 20 64 6f 6e 65 2e 20 54 69 6d 65 20 6c 65 66 74 3a 20 25 64 6d 73 } //Network searching done. Time left: %dms  01 00 
		$a_80_2 = {43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 20 66 61 69 6c 65 64 2c 20 47 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 3d 20 25 78 } //CryptImportKey failed, GetLastError == %x  02 00 
		$a_01_3 = {c7 03 44 72 62 52 66 89 43 15 } //01 00 
		$a_01_4 = {b8 42 4d 00 00 53 66 89 45 a0 } //01 00 
		$a_01_5 = {c7 45 d8 08 02 00 00 c7 45 dc 01 68 00 00 89 75 e0 } //01 00 
		$a_01_6 = {c7 06 06 02 00 00 c7 46 04 00 a4 00 00 c7 46 08 52 53 41 31 } //01 00 
		$a_01_7 = {b8 ba ba ba ab 39 46 04 75 11 } //01 00 
		$a_01_8 = {f6 45 08 08 b9 ba ba ba ab 89 30 89 48 04 89 4c 30 08 } //01 00 
		$a_01_9 = {8d 46 f8 8b 10 50 b9 ef be ad de } //00 00 
	condition:
		any of ($a_*)
 
}