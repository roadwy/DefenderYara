
rule Ransom_Win32_Ergop_C{
	meta:
		description = "Ransom:Win32/Ergop.C,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0c 00 00 "
		
	strings :
		$a_01_0 = {25 73 2e 5b 63 68 69 6e 65 73 33 34 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 68 5d 2e 67 72 79 70 68 6f 6e } //1 %s.[chines34@protonmail.ch].gryphon
		$a_01_1 = {63 68 69 6e 65 73 33 34 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 68 } //1 chines34@protonmail.ch
		$a_01_2 = {6f 63 65 61 6e 6e 65 77 5f 76 62 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 oceannew_vb@protonmail.com
		$a_01_3 = {53 57 34 67 63 33 56 69 61 6d 56 6a 64 43 42 73 61 57 35 6c 49 48 64 79 61 58 52 6c 49 43 4a 6c 62 6d 4e 79 65 58 42 30 61 57 39 75 49 69 42 68 62 6d 51 67 59 58 52 30 } //2 SW4gc3ViamVjdCBsaW5lIHdyaXRlICJlbmNyeXB0aW9uIiBhbmQgYXR0
		$a_01_4 = {44 51 70 5a 62 33 56 79 49 48 42 6c 63 6e 4e 76 62 6d 46 73 49 47 6c 6b 5a 57 35 30 61 57 5a 70 59 32 46 30 61 57 39 75 49 47 35 31 62 57 4a 6c 63 6a 6f 4e 43 67 3d 3d } //2 DQpZb3VyIHBlcnNvbmFsIGlkZW50aWZpY2F0aW9uIG51bWJlcjoNCg==
		$a_01_5 = {52 31 4a 5a 55 45 68 50 54 69 42 53 51 55 35 54 54 30 31 58 51 56 4a 46 } //2 R1JZUEhPTiBSQU5TT01XQVJF
		$a_01_6 = {4d 49 47 66 4d 41 30 47 43 53 71 47 53 49 62 33 44 51 45 42 41 51 55 41 41 34 47 4e 41 44 43 42 69 51 4b 42 67 51 43 72 67 70 50 41 38 52 58 77 48 6e 43 55 43 56 71 57 } //1 MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrgpPA8RXwHnCUCVqW
		$a_01_7 = {21 23 23 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 20 23 23 21 2e 74 78 74 } //1 !## DECRYPT FILES ##!.txt
		$a_01_8 = {2e 67 72 79 70 68 6f 6e } //1 .gryphon
		$a_01_9 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //2 /c vssadmin.exe Delete Shadows /All /Quiet
		$a_01_10 = {2f 63 20 62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //2 /c bcdedit.exe /set {default} recoveryenabled No
		$a_01_11 = {2f 63 20 62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //2 /c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2) >=10
 
}