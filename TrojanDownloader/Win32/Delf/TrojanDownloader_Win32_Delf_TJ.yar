
rule TrojanDownloader_Win32_Delf_TJ{
	meta:
		description = "TrojanDownloader:Win32/Delf.TJ,SIGNATURE_TYPE_PEHSTR,0a 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {e8 81 ef ff ff e9 80 00 00 00 8d 45 f8 50 8b 55 fc b8 98 31 00 10 e8 73 eb ff ff 8b c8 49 ba 01 00 00 00 8b 45 fc e8 db ea ff ff 8d 45 f0 50 b9 02 00 00 00 ba 01 00 00 00 8b 45 f8 e8 c5 ea ff ff 8b 45 f0 e8 61 ea ff ff 50 e8 17 ef ff ff 83 f8 03 75 24 8b 45 f8 e8 4e ea ff ff 8d 55 f4 52 6a 00 50 68 40 30 00 10 6a 00 6a 00 e8 c5 ee ff ff 6a 0a e8 6e ef ff ff } //4
		$a_01_1 = {00 00 48 74 6d 6c 41 64 64 00 55 8b } //2
		$a_01_2 = {6e 74 73 6f 6b 65 6c 65 2e 65 78 65 00 00 00 00 52 65 6d 6f 74 65 20 48 65 6c 70 20 53 65 73 73 69 6f 6e 20 4d 61 6e 61 67 65 72 00 ff ff ff ff 08 00 00 00 52 61 73 61 75 74 6f 6c } //3
		$a_01_3 = {ba 9c 31 00 10 b8 54 39 00 10 e8 bd fe ff ff c3 ff ff ff ff 0b 00 00 00 73 76 63 68 6f 73 74 2e 65 78 65 } //1
		$a_01_4 = {43 6f 6d 73 70 65 63 00 ff ff ff ff 09 00 00 00 20 2f 63 20 64 65 6c } //1
		$a_01_5 = {50 6f 72 74 69 6f 6e 73 20 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 39 2c 32 30 30 33 20 41 76 65 6e 67 65 72 20 62 79 20 4e 68 54 } //1 Portions Copyright (c) 1999,2003 Avenger by NhT
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}