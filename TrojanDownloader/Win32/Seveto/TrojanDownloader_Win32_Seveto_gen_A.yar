
rule TrojanDownloader_Win32_Seveto_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Seveto.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {0f b7 fb 8b 55 00 8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 66 ff 4c 24 04 } //1
		$a_01_1 = {45 34 39 34 56 7a 53 54 6a 4c 4e 68 46 39 4c } //1 E494VzSTjLNhF9L
		$a_01_2 = {47 39 52 32 56 33 4d 54 4d 65 42 4d 76 39 47 2b 2f 42 } //1 G9R2V3MTMeBMv9G+/B
		$a_01_3 = {4b 39 6b 43 4f 6c 39 2f 6f 77 78 42 41 54 31 76 44 4f 63 38 6a 30 50 } //1 K9kCOl9/owxBAT1vDOc8j0P
		$a_10_4 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00 } //1 C:\WINDOWS\svcs.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_10_4  & 1)*1) >=5
 
}