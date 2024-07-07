
rule Ransom_MSIL_BlackSkull_YAA_MTB{
	meta:
		description = "Ransom:MSIL/BlackSkull.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_2 = {4e 6f 43 72 79 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 NoCry.My.Resources
		$a_01_3 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //1 GetLogicalDrives
		$a_01_4 = {41 45 53 5f 45 6e 63 72 79 70 74 } //1 AES_Encrypt
		$a_01_5 = {66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 files are encrypted
		$a_01_6 = {64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 79 6f 20 6e 65 65 64 20 74 6f 20 70 61 79 } //1 decrypt your files, yo need to pay
		$a_01_7 = {48 6f 77 20 44 6f 20 49 20 50 61 79 3f } //1 How Do I Pay?
		$a_01_8 = {62 75 79 20 73 6f 6d 65 20 62 69 74 63 6f 69 6e } //1 buy some bitcoin
		$a_01_9 = {42 00 6c 00 61 00 63 00 6b 00 53 00 6b 00 75 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 BlackSkull.exe
		$a_01_10 = {52 00 65 00 63 00 6f 00 76 00 65 00 72 00 5f 00 59 00 6f 00 75 00 72 00 5f 00 46 00 69 00 6c 00 65 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 Recover_Your_Files.html
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}