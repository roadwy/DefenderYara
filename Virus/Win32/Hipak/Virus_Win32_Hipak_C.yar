
rule Virus_Win32_Hipak_C{
	meta:
		description = "Virus:Win32/Hipak.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 6a ff 68 90 01 04 68 90 01 04 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 5f 57 ff 15 90 01 04 59 83 0d 90 01 04 ff 83 0d 90 01 04 ff ff 15 90 01 04 8b 0d 90 01 04 89 08 ff 15 90 01 04 8b 0d 90 01 04 89 08 a1 90 01 04 8b 00 a3 90 01 04 e8 f4 01 00 00 39 1d 90 01 04 75 0c 68 90 01 04 ff 15 90 01 04 59 e8 c0 01 00 00 68 90 00 } //01 00 
		$a_02_1 = {b1 6d b2 30 b0 68 88 9d ec 90 01 03 c6 85 ed 90 01 03 79 88 9d ee 90 01 03 c6 85 ef 90 01 03 74 c6 85 f0 90 01 03 65 90 00 } //02 00 
		$a_02_2 = {5f 49 6e 73 74 61 6c 6c 46 69 6c 74 65 72 40 38 00 90 02 20 2e 00 64 00 6c 00 6c 00 90 02 10 2f 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 00 00 00 00 00 00 00 00 6f 70 65 6e 00 00 00 00 2f 61 75 74 6f 72 75 6e 00 90 02 40 00 2e 72 65 6c 6f 63 00 00 5c 00 00 00 2a 2e 2a 00 61 3a 5c 00 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 2d 00 00 00 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Virus_Win32_Hipak_C_2{
	meta:
		description = "Virus:Win32/Hipak.C,SIGNATURE_TYPE_PEHSTR,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 84 0d 58 f2 ff ff 5c 41 c6 84 0d 58 f2 ff ff 64 41 c6 84 0d 58 f2 ff ff 72 41 c6 84 0d 58 f2 ff ff 69 41 c6 84 0d 58 f2 ff ff 76 41 c6 84 0d 58 f2 ff ff 65 41 c6 84 0d 58 f2 ff ff 72 41 88 9c 0d 58 f2 ff ff 41 c6 84 0d 58 f2 ff ff 5c 41 88 9c 0d 58 f2 ff ff 41 c6 84 0d 58 f2 ff ff 76 41 c6 84 0d 58 f2 ff ff 63 41 c6 84 0d 58 f2 ff ff 68 41 c6 84 0d 58 f2 ff ff 6f 41 88 9c 0d 58 f2 ff ff 41 c6 84 0d 58 f2 ff ff 74 41 c6 84 0d 58 f2 ff ff 2e 41 c6 84 0d 58 f2 ff ff 65 41 c6 84 0d 58 f2 ff ff 78 41 c6 84 0d } //01 00 
		$a_01_1 = {58 f2 ff ff 65 41 c6 84 0d 58 f2 ff ff 20 41 c6 84 0d 58 f2 ff ff 2f 41 c6 84 0d 58 f2 ff ff 61 41 8d bd 58 f2 ff ff 8d 95 fc fe ff ff c6 84 0d 58 f2 ff ff 75 41 c6 84 0d 58 f2 ff ff 74 41 c6 84 0d 58 f2 ff ff 6f 41 c6 84 0d 58 f2 ff ff 72 41 c6 84 0d 58 f2 ff ff 75 41 c6 84 0d 58 f2 ff ff 6e } //01 00 
		$a_01_2 = {6f 70 65 6e 00 00 00 00 2f 61 75 74 6f 72 75 6e 00 00 00 00 6b 73 63 76 00 00 00 00 49 6e 65 74 49 6e 66 6f 00 00 00 00 30 34 00 00 2e 72 65 6c 6f 63 00 00 5c 00 00 00 2a 2e 2a 00 61 3a 5c 00 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 2d 00 00 00 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}