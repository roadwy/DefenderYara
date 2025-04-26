
rule TrojanDownloader_Win32_Desecreter_A{
	meta:
		description = "TrojanDownloader:Win32/Desecreter.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 00 00 00 ff ff ff ff 01 00 00 00 22 00 00 00 6f 70 65 6e 00 00 00 00 } //1
		$a_01_1 = {65 74 47 65 74 20 76 31 2e 30 20 62 79 20 52 30 44 72 31 67 30 00 00 00 04 00 00 00 } //1
		$a_01_2 = {09 00 00 00 62 75 69 6c 64 2e 64 6c 6c 00 00 00 ff ff ff ff 7b 00 00 00 41 20 44 4c } //1
		$a_01_3 = {57 00 00 00 ff ff ff ff 06 00 00 00 6b 69 6c 6c 41 76 00 00 ff ff ff ff 06 00 00 00 64 77 45 78 65 63 00 00 ff ff ff ff 06 00 00 00 64 77 46 69 } //1
		$a_01_4 = {0e 00 00 00 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 00 00 ff ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}