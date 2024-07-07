
rule TrojanDownloader_Win32_Bancos_H{
	meta:
		description = "TrojanDownloader:Win32/Bancos.H,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {7e 50 89 45 f0 bf 01 00 00 00 8b 45 fc 8a 5c 38 ff 80 e3 0f 8b 45 f4 8a 44 30 ff 24 0f 32 d8 80 f3 0a } //3
		$a_01_1 = {4f 75 72 20 46 57 42 20 69 73 20 4c 6f 61 64 65 64 00 } //1
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 20 46 69 6c 65 20 2e 2e 2e 00 } //1
		$a_01_3 = {52 75 6e 6e 69 6e 67 20 44 6f 77 6e 6c 6f 61 64 65 64 20 46 69 6c 65 20 2e 2e 2e 00 } //1
		$a_01_4 = {66 77 62 64 6c 6c 2e 64 6c 6c 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=5
 
}