
rule Trojan_Win64_GoKrypt_AB_MTB{
	meta:
		description = "Trojan:Win64/GoKrypt.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //02 00  Go build ID:
		$a_01_1 = {67 77 4d 44 45 77 4d 44 41 77 4d 44 51 78 59 6a 6b 30 4d 44 41 77 4d 44 41 77 4d 44 51 78 59 6d 45 31 4f 47 45 30 4e 54 4e 6c 4e 57 5a 6d 5a 44 55 30 4f 44 6b 7a 4e 54 4d 31 4d 7a 51 34 4f 44 6c 6c 4e 7a 51 34 4f 44 6c } //02 00  gwMDEwMDAwMDQxYjk0MDAwMDAwMDQxYmE1OGE0NTNlNWZmZDU0ODkzNTM1MzQ4ODllNzQ4ODl
		$a_01_2 = {6d 4d 54 51 34 4f 44 6c 6b 59 54 51 78 59 6a 67 77 4d 44 49 77 4d 44 41 77 4d 44 51 35 4f 44 6c 6d 4f 54 51 78 59 6d 45 78 4d 6a 6b 32 4f 44 6c 6c 4d 6d 5a 6d 5a 44 55 30 4f 44 67 7a 59 7a 51 79 4d 44 67 31 59 7a 41 33 4e 47 49 32 4e 6a 59 34 59 } //00 00  mMTQ4ODlkYTQxYjgwMDIwMDAwMDQ5ODlmOTQxYmExMjk2ODllMmZmZDU0ODgzYzQyMDg1YzA3NGI2NjY4Y
	condition:
		any of ($a_*)
 
}