
rule TrojanSpy_Win32_Hormelex_D{
	meta:
		description = "TrojanSpy:Win32/Hormelex.D,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 31 35 46 39 31 42 38 36 41 44 30 30 41 33 41 45 42 } //10 C15F91B86AD00A3AEB
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 79 73 74 65 6d 6a 68 6f 63 6b 6f 67 79 6e 2e 63 6f 6d 2e 62 72 2f 62 6f 61 2e 70 68 70 } //10 http://systemjhockogyn.com.br/boa.php
		$a_01_2 = {74 6f 3d 6e 65 74 6f 39 30 30 31 66 74 70 40 67 6d 61 69 6c 2e 63 6f 6d } //1 to=neto9001ftp@gmail.com
		$a_01_3 = {73 75 62 6a 65 63 74 3d 4d 6f 6e 74 6f 79 61 2d 50 43 } //1 subject=Montoya-PC
		$a_01_4 = {39 30 41 44 36 36 38 39 41 44 36 44 39 33 34 46 33 43 45 37 32 46 44 32 } //1 90AD6689AD6D934F3CE72FD2
		$a_01_5 = {36 32 38 42 34 32 46 30 32 32 44 44 35 39 43 31 42 31 35 35 38 43 41 42 } //1 628B42F022DD59C1B1558CAB
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=12
 
}