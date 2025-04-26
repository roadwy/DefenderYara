
rule Spammer_Win32_Mapegost_A{
	meta:
		description = "Spammer:Win32/Mapegost.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 c0 02 66 89 0a 0f b7 08 83 c2 02 83 f9 22 75 } //1
		$a_01_1 = {0f be d0 8a 41 01 33 fa 6b ff 71 41 0f cf 84 c0 } //1
		$a_01_2 = {73 70 61 6d 67 65 74 2e 70 68 70 } //1 spamget.php
		$a_03_3 = {6d 6f 64 65 3d 67 65 74 [0-08] 26 75 69 64 3d 25 73 26 6f 73 3d 25 73 26 70 69 64 3d 25 73 26 66 6c 61 67 73 3d 25 73 26 73 65 6e 74 3d 25 69 26 61 63 63 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}