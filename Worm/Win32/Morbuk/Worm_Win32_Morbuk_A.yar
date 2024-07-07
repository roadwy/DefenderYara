
rule Worm_Win32_Morbuk_A{
	meta:
		description = "Worm:Win32/Morbuk.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 37 3c 3a 88 04 1f 74 0d 47 89 34 24 } //2
		$a_01_1 = {0f be ca 83 38 01 74 b2 89 0c 24 b8 03 01 00 00 89 44 24 04 } //2
		$a_03_2 = {83 ec 04 83 f8 02 75 90 01 01 89 34 24 fe c3 e8 90 01 04 80 fb 5a 7e c7 90 00 } //2
		$a_01_3 = {5b 41 75 74 6f 52 75 6e 5d } //1 [AutoRun]
		$a_01_4 = {3b 73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 3d 4d 61 6e 61 67 65 72 28 26 58 29 } //1 ;shell\explore=Manager(&X)
		$a_01_5 = {2e 70 68 70 3f 63 6f 6d 70 3d 25 73 26 6d 73 67 3d 25 73 } //1 .php?comp=%s&msg=%s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}