
rule Trojan_BAT_SpySnake_MM_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 03 11 01 11 03 11 01 8e 69 5d 91 03 11 03 91 61 d2 9c 38 ?? ?? ?? ff 11 04 2a } //10
		$a_01_1 = {44 65 73 74 72 6f 79 50 75 62 6c 69 73 68 65 72 } //1 DestroyPublisher
		$a_01_2 = {45 6e 61 62 6c 65 50 72 6f 78 79 } //1 EnableProxy
		$a_01_3 = {4d 61 6e 61 67 65 50 75 62 6c 69 73 68 65 72 } //1 ManagePublisher
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_5 = {52 65 6d 6f 76 65 50 72 6f 78 79 } //1 RemoveProxy
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_BAT_SpySnake_MM_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 9f a2 2b 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 b0 00 00 00 30 00 00 00 5e 01 00 00 19 03 00 00 b9 01 00 00 1b 00 00 00 4a } //10
		$a_01_1 = {63 36 35 65 37 35 32 35 2d 64 66 34 66 2d 34 63 32 34 2d 61 63 66 64 2d 34 30 64 61 32 64 31 38 33 63 64 38 } //5 c65e7525-df4f-4c24-acfd-40da2d183cd8
		$a_01_2 = {4c 30 30 30 30 30 } //1 L00000
		$a_01_3 = {43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5f 00 52 00 75 00 6e 00 } //1 Control_Run
		$a_01_4 = {4b 30 30 30 30 30 31 } //1 K000001
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=18
 
}