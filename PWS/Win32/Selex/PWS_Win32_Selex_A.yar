
rule PWS_Win32_Selex_A{
	meta:
		description = "PWS:Win32/Selex.A,SIGNATURE_TYPE_PEHSTR_EXT,ffffffde 00 ffffffdc 00 0c 00 00 "
		
	strings :
		$a_02_0 = {b9 a5 0e 00 00 33 c0 bf 90 01 03 00 52 f3 ab 66 ab 68 97 3a 00 00 6a 01 68 90 01 03 00 aa e8 90 01 03 00 8b 15 90 01 03 00 52 e8 90 00 } //100
		$a_00_1 = {89 45 f8 89 45 fc b8 01 00 00 00 0f a2 89 45 f8 89 55 fc 8b 4d f8 8b 55 fc 33 c0 33 f6 0b c1 0b d6 } //100
		$a_00_2 = {51 55 49 44 3d 25 75 2d 25 49 36 34 75 2d } //4 QUID=%u-%I64u-
		$a_00_3 = {53 4d 54 50 3d 25 73 26 50 4f 50 33 3d 25 73 26 4e 4f 4d 45 3d 25 73 26 41 44 44 52 3d 25 73 26 55 53 45 52 3d 25 73 26 50 41 53 53 3d 25 73 } //4 SMTP=%s&POP3=%s&NOME=%s&ADDR=%s&USER=%s&PASS=%s
		$a_00_4 = {45 6e 63 6f 64 69 6e 67 20 74 6f 6f 6b 20 25 64 6d 73 } //4 Encoding took %dms
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //4 Software\Microsoft\Internet Account Manager\Accounts
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 55 73 65 72 20 41 67 65 6e 74 5c 50 6f 73 74 20 50 6c 61 74 66 6f 72 6d } //4 SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\User Agent\Post Platform
		$a_00_7 = {50 4f 50 33 20 55 73 65 72 20 4e 61 6d 65 } //1 POP3 User Name
		$a_00_8 = {50 4f 50 33 20 53 65 72 76 65 72 } //1 POP3 Server
		$a_00_9 = {45 48 4c 4f 20 25 73 } //1 EHLO %s
		$a_00_10 = {25 73 5c 62 6f 64 79 2e 74 78 74 } //1 %s\body.txt
		$a_00_11 = {25 73 5c 73 75 62 6a 65 63 74 2e 74 78 74 } //1 %s\subject.txt
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*4+(#a_00_3  & 1)*4+(#a_00_4  & 1)*4+(#a_00_5  & 1)*4+(#a_00_6  & 1)*4+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1) >=220
 
}