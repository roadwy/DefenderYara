
rule Trojan_BAT_Downloader_BO_MTB{
	meta:
		description = "Trojan:BAT/Downloader.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 42 41 32 4b 32 31 20 48 41 43 4b 20 62 79 20 62 69 72 61 } //01 00  NBA2K21 HACK by bira
		$a_01_1 = {44 65 63 72 79 70 74 53 65 72 76 69 63 65 } //01 00  DecryptService
		$a_01_2 = {45 6e 63 72 79 70 74 53 65 72 76 69 63 65 } //01 00  EncryptService
		$a_01_3 = {44 65 63 72 79 70 74 53 74 72 69 6e 67 } //01 00  DecryptString
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {4d 61 6c 69 63 69 6f 75 73 43 68 65 63 6b } //01 00  MaliciousCheck
		$a_01_6 = {4f 62 66 75 73 63 61 74 65 } //01 00  Obfuscate
		$a_01_7 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 44 00 57 00 48 00 6b 00 77 00 38 00 69 00 31 00 } //01 00  https://pastebin.com/raw/DWHkw8i1
		$a_01_8 = {45 6e 63 72 79 70 74 53 74 72 69 6e 67 } //01 00  EncryptString
		$a_01_9 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}