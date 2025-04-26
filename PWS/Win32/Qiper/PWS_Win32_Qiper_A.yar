
rule PWS_Win32_Qiper_A{
	meta:
		description = "PWS:Win32/Qiper.A,SIGNATURE_TYPE_PEHSTR,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 66 69 6c 65 2e 71 69 70 2e 72 75 2f 66 69 6c 65 2f } //1 http://file.qip.ru/file/
		$a_01_1 = {51 49 50 5c 50 72 6f 66 69 6c 65 73 5c } //1 QIP\Profiles\
		$a_01_2 = {74 69 74 6c 65 3d 22 41 49 4d 22 } //1 title="AIM"
		$a_01_3 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_4 = {47 65 74 57 69 6e 64 6f 77 54 65 78 74 41 } //1 GetWindowTextA
		$a_01_5 = {51 49 50 20 2d 20 d1 ef ee ea ee e9 ed ee e5 20 ee e1 f9 e5 ed e8 e5 21 } //1
		$a_01_6 = {8a 45 ff 04 e0 2c 5f 72 06 04 bf 2c 40 73 1c } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*10) >=16
 
}