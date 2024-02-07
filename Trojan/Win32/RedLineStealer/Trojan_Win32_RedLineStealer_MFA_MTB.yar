
rule Trojan_Win32_RedLineStealer_MFA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 75 41 6d 6d 77 6d 6a 70 } //01 00  OuAmmwmjp
		$a_01_1 = {4a 68 57 71 66 71 41 7c 66 } //01 00  JhWqfqA|f
		$a_01_2 = {50 61 73 73 77 6f 72 64 73 } //01 00  Passwords
		$a_01_3 = {45 6e 63 72 79 70 74 69 6f 6e 20 63 6f 6e 73 74 61 6e 74 73 } //01 00  Encryption constants
		$a_01_4 = {65 6e 63 72 79 70 74 69 6f 6e 20 73 65 63 74 69 6f 6e 28 73 29 20 6d 69 67 68 74 20 6e 6f 74 20 62 65 20 70 72 6f 70 65 72 6c 79 20 64 65 63 72 79 70 74 65 64 } //01 00  encryption section(s) might not be properly decrypted
		$a_01_5 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_6 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 41 } //01 00  GetDiskFreeSpaceA
		$a_01_7 = {57 53 41 49 73 42 6c 6f 63 6b 69 6e 67 } //01 00  WSAIsBlocking
		$a_01_8 = {72 00 71 00 62 00 77 00 6a 00 71 00 62 00 77 00 6a 00 33 00 34 00 35 00 6e 00 33 00 } //00 00  rqbwjqbwj345n3
	condition:
		any of ($a_*)
 
}