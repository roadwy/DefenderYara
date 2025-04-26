
rule TrojanSpy_Win32_Talsab_C{
	meta:
		description = "TrojanSpy:Win32/Talsab.C,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 33 31 33 33 34 2e 69 6e 66 6f 2f 31 73 74 65 6d 61 69 6c 2e 70 68 70 } //4 http://www.31334.info/1stemail.php
		$a_01_1 = {63 6d 64 20 2f 63 20 52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 56 20 72 75 6e 64 6c 6c 20 2f 44 20 22 5c 22 } //3 cmd /c REG ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V rundll /D "\"
		$a_01_2 = {26 63 6f 6e 74 65 75 64 6f 3d } //2 &conteudo=
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=9
 
}