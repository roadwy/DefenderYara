
rule Backdoor_Win32_Poison_Y{
	meta:
		description = "Backdoor:Win32/Poison.Y,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_03_0 = {7e 25 bf 01 00 00 00 8d 45 f8 8b 55 fc 8a 54 3a ff 80 f2 ?? e8 ?? ?? fe ff 8b 55 f8 8b c6 e8 ?? ?? fe ff 47 4b 75 e0 } //3
		$a_03_1 = {74 58 b8 61 09 00 00 e8 ?? ?? ff ff 89 45 00 33 c0 89 07 6a 00 57 68 60 09 00 00 } //2
		$a_01_2 = {54 57 65 62 43 61 6d 54 68 72 65 61 64 } //1 TWebCamThread
		$a_01_3 = {54 44 6f 77 6e 46 69 6c 65 54 68 72 65 61 64 } //1 TDownFileThread
		$a_01_4 = {54 53 63 72 65 65 6e 53 70 79 } //1 TScreenSpy
		$a_01_5 = {00 2e 6b 6c 67 00 } //1 ⸀汫g
		$a_03_6 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00 00 [0-05] 2e 5c 53 4d 41 52 54 56 53 44 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=8
 
}