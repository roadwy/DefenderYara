
rule Ransom_Win32_Tescrypt_Q{
	meta:
		description = "Ransom:Win32/Tescrypt.Q,SIGNATURE_TYPE_PEHSTR,06 00 06 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {53 75 62 3d 25 73 26 64 68 3d 25 73 26 61 64 64 72 3d 25 73 26 73 69 7a 65 3d 25 6c 6c 64 26 76 65 72 73 69 6f 6e 3d 34 2e 30 26 4f 53 3d 25 6c 64 26 49 44 3d 25 64 26 69 6e 73 74 5f 69 64 3d 25 58 25 58 25 58 25 58 25 58 25 58 25 58 25 58 } //02 00  Sub=%s&dh=%s&addr=%s&size=%lld&version=4.0&OS=%ld&ID=%d&inst_id=%X%X%X%X%X%X%X%X
		$a_01_1 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 69 64 65 6e 74 69 66 69 63 61 74 69 6f 6e 20 49 44 3a 20 25 53 } //02 00  Your personal identification ID: %S
		$a_01_2 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 70 61 67 65 20 54 6f 72 2d 42 72 6f 77 73 65 72 } //02 00  Your personal page Tor-Browser
		$a_01_3 = {6e 6f 20 6f 74 68 65 72 20 6f 70 74 69 6f 6e 20 72 61 74 68 65 72 20 74 68 61 6e 20 70 61 79 69 6e 67 } //02 00  no other option rather than paying
		$a_01_4 = {59 6f 75 20 77 6f 6e 27 74 20 62 65 20 61 62 6c 65 20 74 6f 20 75 73 65 2c 20 72 65 61 64 2c 20 73 65 65 20 6f 72 20 77 6f 72 6b 20 77 69 74 68 20 74 68 65 6d 20 61 6e 79 6d 6f 72 65 } //01 00  You won't be able to use, read, see or work with them anymore
		$a_01_5 = {2e 6f 6e 69 6f 6e 2f 25 53 0d 0a } //01 00 
		$a_01_6 = {2e 63 6f 6d 2f 25 53 0d 0a } //01 00 
		$a_01_7 = {2e 61 74 2f 25 53 0d 0a } //00 00 
		$a_01_8 = {00 67 16 00 } //00 1f 
	condition:
		any of ($a_*)
 
}