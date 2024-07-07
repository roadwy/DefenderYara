
rule Virus_Win32_Viking_gen_dll{
	meta:
		description = "Virus:Win32/Viking.gen!dll,SIGNATURE_TYPE_PEHSTR,0d 00 0c 00 0a 00 00 "
		
	strings :
		$a_01_0 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 } //3
		$a_01_1 = {d5 d2 cc c4 ef f7 ee ec ef e1 e4 d4 ef c6 e9 ec } //3
		$a_01_2 = {dc ed e9 e3 f2 ef f3 ef e6 f4 dc } //3
		$a_01_3 = {e8 f4 f4 f0 ba af af } //2
		$a_01_4 = {63 3a 5c 31 2e 74 78 74 } //1 c:\1.txt
		$a_01_5 = {64 33 3a 00 ff ff ff ff 03 } //1
		$a_01_6 = {64 34 3a 00 ff ff ff ff 03 } //1
		$a_01_7 = {41 43 44 53 65 65 34 2e 65 78 65 } //1 ACDSee4.exe
		$a_01_8 = {55 65 64 69 74 33 32 2e 65 78 65 } //1 Uedit32.exe
		$a_01_9 = {20 2f 68 65 68 65 } //1  /hehe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=12
 
}