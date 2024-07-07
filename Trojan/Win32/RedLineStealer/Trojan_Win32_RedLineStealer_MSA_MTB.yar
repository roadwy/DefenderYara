
rule Trojan_Win32_RedLineStealer_MSA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2e 51 68 45 36 6b 74 65 } //1 .QhE6kte
		$a_01_1 = {62 6c 61 63 6b 6c 69 73 74 65 64 20 6b 65 79 } //1 blacklisted key
		$a_01_2 = {45 6e 63 72 79 70 74 69 6f 6e 20 63 6f 6e 73 74 61 6e 74 73 } //1 Encryption constants
		$a_01_3 = {65 6e 63 72 79 70 74 69 6f 6e 20 73 65 63 74 69 6f 6e 28 73 29 20 6d 69 67 68 74 20 6e 6f 74 20 62 65 20 70 72 6f 70 65 72 6c 79 20 64 65 63 72 79 70 74 65 64 } //1 encryption section(s) might not be properly decrypted
		$a_01_4 = {50 61 73 73 77 6f 72 64 73 } //1 Passwords
		$a_01_5 = {47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 } //1 GetKeyboardType
		$a_01_6 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}