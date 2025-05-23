
rule Trojan_Win32_Selfdel_B{
	meta:
		description = "Trojan:Win32/Selfdel.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 2e 00 31 00 2e 00 31 00 2e 00 31 00 20 00 2d 00 6e 00 20 00 31 00 20 00 2d 00 77 00 20 00 33 00 30 00 30 00 30 00 20 00 3e 00 20 00 4e 00 75 00 6c 00 20 00 26 00 20 00 44 00 65 00 6c 00 20 00 22 00 25 00 73 00 22 00 } //2 cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del "%s"
		$a_01_1 = {ff 75 0c ff d7 59 84 c0 59 74 47 8d 85 c4 fd ff ff 50 53 53 6a 28 53 e8 } //1
		$a_01_2 = {ff 75 0c ff d7 59 84 c0 59 0f 85 c2 01 00 00 68 } //1
		$a_01_3 = {ff d6 59 84 c0 59 75 37 8d 45 d4 50 68 } //1
		$a_01_4 = {39 9d 6c ff ff ff 0f 84 e8 00 00 00 39 9d 5c ff ff ff 0f 84 dc 00 00 00 38 5d f2 75 0c 38 5d f3 c7 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}