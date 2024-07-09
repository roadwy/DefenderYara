
rule TrojanSpy_Win32_Vinelai_A{
	meta:
		description = "TrojanSpy:Win32/Vinelai.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 65 6e 76 69 61 6d 61 69 6c 2e 70 68 70 } //1 /enviamail.php
		$a_01_1 = {44 33 33 37 41 39 32 46 39 43 33 32 41 30 33 42 46 36 30 32 30 34 35 41 41 38 37 37 38 43 00 } //1
		$a_03_2 = {be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00 8d 55 d0 33 c9 b8 ?? ?? ?? ?? e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}