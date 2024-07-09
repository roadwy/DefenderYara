
rule TrojanDownloader_Win32_Banload_BAF{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {35 2e 74 78 74 [0-10] 6d 69 6e 69 66 65 73 74 2e 6a 73 6f 6e } //1
		$a_03_1 = {34 2e 74 78 74 [0-10] 69 63 6f 6e 2e 70 6e 67 } //1
		$a_03_2 = {32 2e 6a 70 67 [0-10] 32 2e 74 78 74 } //1
		$a_01_3 = {5c 44 61 64 6f 73 20 64 65 20 61 70 6c 69 63 61 74 69 76 6f 73 5c } //1 \Dados de aplicativos\
		$a_01_4 = {71 5a 50 43 7a 67 36 4a 44 77 31 4c 42 4e 72 5a 69 67 66 55 7a 63 62 5a 7a 78 72 37 41 77 39 4e 43 31 58 48 42 67 57 47 44 78 6e 4c 43 4e 6e 43 7a 67 76 5a 41 32 72 56 43 66 58 } //1 qZPCzg6JDw1LBNrZigfUzcbZzxr7Aw9NC1XHBgWGDxnLCNnCzgvZA2rVCfX
		$a_01_5 = {74 77 4c 4a 43 4d 36 5a 42 38 7a 37 78 65 4c 55 44 67 76 59 42 4d 76 37 69 65 76 33 43 67 58 56 43 4d 76 59 78 66 66 31 41 77 6e 52 69 65 58 48 44 77 39 4a 41 66 58 } //1 twLJCM6ZB8z7xeLUDgvYBMv7iev3CgXVCMvYxff1AwnRieXHDw9JAfX
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}