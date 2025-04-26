
rule TrojanDownloader_Win32_Xolondox_A{
	meta:
		description = "TrojanDownloader:Win32/Xolondox.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {58 4c 58 4e 44 58 53 00 25 64 2e 67 69 66 } //1 䱘乘塄S搥朮晩
		$a_01_1 = {73 5c 51 65 64 69 72 5c 2a 2e 2a } //1 s\Qedir\*.*
		$a_01_2 = {25 73 3f 6d 61 63 3d 25 73 26 75 73 65 72 69 64 3d 25 73 26 6a 69 6e 63 68 65 6e 67 73 68 75 3d 25 64 } //1 %s?mac=%s&userid=%s&jinchengshu=%d
		$a_01_3 = {46 69 6c 65 73 5c 39 33 33 2e 74 78 74 } //1 Files\933.txt
		$a_01_4 = {67 72 72 68 74 68 74 75 37 36 36 35 36 } //1 grrhthtu76656
		$a_01_5 = {c6 45 a8 68 c6 45 a9 74 c6 45 aa 74 c6 45 ab 70 c6 45 ac 3a c6 45 ad 2f c6 45 ae 2f } //4
		$a_01_6 = {c6 45 d4 63 c6 45 d5 6f c6 45 d6 6e c6 45 d7 69 c6 45 d8 6d } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*4+(#a_01_6  & 1)*4) >=8
 
}