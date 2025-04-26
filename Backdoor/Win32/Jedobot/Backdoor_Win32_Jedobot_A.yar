
rule Backdoor_Win32_Jedobot_A{
	meta:
		description = "Backdoor:Win32/Jedobot.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {25 41 50 50 44 41 54 41 25 5c 73 6d 73 73 2e 65 78 65 } //3 %APPDATA%\smss.exe
		$a_01_1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 6d 73 73 2e 65 78 65 } //2 %SystemRoot%\smss.exe
		$a_01_2 = {3f 70 3d 42 6f 74 52 65 67 69 73 74 65 72 26 } //1 ?p=BotRegister&
		$a_01_3 = {64 64 6f 73 2e 74 63 70 } //1 ddos.tcp
		$a_01_4 = {62 6f 74 6d 61 6a 6f 72 3d } //1 botmajor=
		$a_01_5 = {62 6f 74 63 6f 75 6e 74 72 79 3d } //1 botcountry=
		$a_01_6 = {3f 70 3d 42 6f 74 50 6f 6b 65 } //1 ?p=BotPoke
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}