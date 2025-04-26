
rule Trojan_Win32_ColdCryptor_A{
	meta:
		description = "Trojan:Win32/ColdCryptor.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {43 00 6f 00 6c 00 64 00 43 00 72 00 79 00 70 00 74 00 6f 00 72 00 } //1 ColdCryptor
		$a_00_1 = {63 6f 6c 64 63 72 79 70 74 6f 72 2e 65 78 65 } //1 coldcryptor.exe
		$a_01_2 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_01_3 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
		$a_00_4 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 3a 00 } //1 Encrypted:
		$a_01_5 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}