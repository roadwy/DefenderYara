
rule Trojan_Win32_Emotet_DGK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_02_0 = {33 d2 4b 40 b9 57 2b 01 00 f7 f1 8b 74 24 90 01 01 89 9c 24 90 01 04 57 57 8b ca 8a 5c 0c 90 01 01 0f b6 c3 03 c6 33 d2 be 57 2b 01 00 f7 f6 90 00 } //1
		$a_81_1 = {65 49 56 46 75 48 75 38 4d 30 78 7a 45 4c 39 39 54 63 46 34 65 6d 34 6a 53 72 72 4e 46 6a 36 79 66 35 69 66 34 59 76 } //1 eIVFuHu8M0xzEL99TcF4em4jSrrNFj6yf5if4Yv
		$a_81_2 = {6f 34 4b 69 37 70 52 37 35 61 70 6b 66 35 69 38 44 4c 62 73 49 56 4b 4a 47 56 53 73 48 31 38 78 46 6e 52 6d 32 6a } //1 o4Ki7pR75apkf5i8DLbsIVKJGVSsH18xFnRm2j
		$a_81_3 = {4f 4b 35 46 76 48 5a 5a 34 31 4b 7a 45 35 72 4e 36 34 4a 50 44 59 4c 38 30 56 77 7a 6e 56 4c 4b 45 59 32 70 4d 41 49 4a 71 49 58 74 45 6a 4b } //1 OK5FvHZZ41KzE5rN64JPDYL80VwznVLKEY2pMAIJqIXtEjK
		$a_81_4 = {74 68 75 68 54 38 54 6b 67 49 37 34 71 75 53 73 61 6d 36 79 44 78 63 52 68 6c 74 44 6c 53 73 75 63 58 77 61 58 47 4c 50 4a 77 59 48 57 75 57 39 6c 4c 66 47 45 55 79 48 46 37 51 61 47 4c 57 63 } //1 thuhT8TkgI74quSsam6yDxcRhltDlSsucXwaXGLPJwYHWuW9lLfGEUyHF7QaGLWc
		$a_81_5 = {31 75 4c 52 44 54 65 42 } //1 1uLRDTeB
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=1
 
}