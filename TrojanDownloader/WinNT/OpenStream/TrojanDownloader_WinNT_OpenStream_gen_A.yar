
rule TrojanDownloader_WinNT_OpenStream_gen_A{
	meta:
		description = "TrojanDownloader:WinNT/OpenStream.gen!A,SIGNATURE_TYPE_JAVAHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {21 28 4c 63 6f 6d 2f 6d 73 2f 73 65 63 75 72 69 74 79 2f 50 65 72 6d 69 73 73 69 6f 6e 49 44 3b 29 56 } //1 !(Lcom/ms/security/PermissionID;)V
		$a_01_1 = {28 29 4c 6a 61 76 61 2f 6e 65 74 2f 55 52 4c 43 6f 6e 6e 65 63 74 69 6f 6e 3b } //1 ()Ljava/net/URLConnection;
		$a_01_2 = {45 52 52 4f 52 5f 45 58 45 4c 4f 41 44 45 52 } //1 ERROR_EXELOADER
		$a_01_3 = {4d 61 74 72 69 78 2e 6a 61 76 61 } //1 Matrix.java
		$a_01_4 = {63 6f 6d 2f 6d 73 2f 77 69 6e 33 32 2f 4b 65 72 6e 65 6c 33 32 } //1 com/ms/win32/Kernel32
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_WinNT_OpenStream_gen_A_2{
	meta:
		description = "TrojanDownloader:WinNT/OpenStream.gen!A,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {06 61 70 70 65 6e 64 01 00 2d 28 4c 6a 61 76 61 2f 6c 61 6e 67 2f 53 74 72 69 6e 67 3b 29 4c 6a 61 76 61 2f 6c 61 6e 67 2f 53 74 72 69 6e 67 42 75 69 6c 64 65 72 3b 01 00 08 74 6f 53 74 72 69 6e 67 01 } //1
		$a_01_1 = {0e 6f 70 65 6e 43 6f 6e 6e 65 63 74 69 6f 6e 01 00 1a 28 29 4c 6a 61 76 61 2f 6e 65 74 2f 55 52 4c 43 6f 6e 6e 65 63 74 69 6f 6e 3b 01 00 0e 67 65 74 49 6e 70 75 74 53 74 72 65 61 6d 01 00 17 28 29 4c 6a 61 76 61 2f 69 6f 2f 49 6e 70 75 74 53 74 72 65 61 6d 3b 01 00 04 72 65 61 64 01 00 07 28 5b 42 49 49 29 49 01 00 05 77 72 69 74 65 01 00 07 28 5b 42 49 49 29 56 01 00 05 63 6c 6f 73 65 01 } //1
		$a_01_2 = {11 6a 61 76 61 2f 6c 61 6e 67 2f 52 75 6e 74 69 6d 65 01 00 0a 67 65 74 52 75 6e 74 69 6d 65 01 00 15 28 29 4c 6a 61 76 61 2f 6c 61 6e 67 2f 52 75 6e 74 69 6d 65 3b 01 00 04 65 78 65 63 01 } //1
		$a_03_3 = {11 04 00 bc 08 3a ?? 19 ?? 19 ?? 03 19 ?? be b6 00 ?? 59 36 ?? 02 9f 00 ?? (2d|19 ?? 19 ??) 03 15 ?? b6 00 ?? a7 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}