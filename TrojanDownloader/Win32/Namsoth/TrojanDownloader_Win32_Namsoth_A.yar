
rule TrojanDownloader_Win32_Namsoth_A{
	meta:
		description = "TrojanDownloader:Win32/Namsoth.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {b1 6e b2 74 33 db } //2
		$a_01_1 = {88 5c 24 1f c6 44 24 20 49 88 4c 24 21 88 54 24 22 c6 44 24 24 72 88 4c 24 25 88 54 24 27 c6 44 24 28 52 c6 44 24 2a 61 } //2
		$a_01_2 = {26 75 73 65 72 69 64 3d 25 30 34 64 26 6f 74 68 65 72 3d 25 63 25 73 } //1 &userid=%04d&other=%c%s
		$a_01_3 = {20 20 57 61 69 74 20 66 6f 72 20 25 30 32 64 20 6d 69 6e 75 74 65 28 73 29 2e 2e 2e } //1   Wait for %02d minute(s)...
		$a_01_4 = {43 6f 6e 6e 65 63 74 69 6f 6e 20 43 6f 6d 69 6e 67 21 0a 0a } //1 潃湮捥楴湯䌠浯湩Ⅷਊ
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}