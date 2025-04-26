
rule PWS_Win32_Frethog_H{
	meta:
		description = "PWS:Win32/Frethog.H,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b f0 85 f6 74 67 33 ff 81 3e 23 fe 4e f7 8b 46 08 75 5a 85 c0 74 56 81 7e 0c 84 14 1a af 75 4d 83 c0 14 80 38 00 74 39 50 a1 ?? ?? 00 10 69 c0 04 01 00 00 } //1
		$a_01_1 = {25 73 3f 73 65 72 76 65 72 3d 25 73 26 67 61 6d 65 69 64 3d 25 73 26 70 61 73 73 3d 25 73 26 70 69 6e 3d 25 73 26 77 75 70 69 6e 3d 25 73 26 72 6f 6c 65 3d 25 73 26 65 71 75 3d 25 73 26 6f 74 68 65 72 3d 42 75 69 6c 64 3a 25 73 } //1 %s?server=%s&gameid=%s&pass=%s&pin=%s&wupin=%s&role=%s&equ=%s&other=Build:%s
		$a_01_2 = {46 6f 72 74 68 67 6f 6e 65 72 } //1 Forthgoner
		$a_01_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 5c 75 70 64 61 74 65 2e 69 6e 69 } //1 C:\Windows\\update.ini
		$a_01_4 = {2f 70 6f 73 74 2e 61 73 70 } //1 /post.asp
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}