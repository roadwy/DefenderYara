
rule Trojan_Win32_ServStart_C{
	meta:
		description = "Trojan:Win32/ServStart.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_01_0 = {83 c0 03 33 d2 0f af c6 f7 74 24 } //2
		$a_00_1 = {5c a1 b8 bf aa ca bc a1 b9 b2 cb b5 a5 5c b3 cc d0 f2 5c c6 f4 b6 af 5c } //2
		$a_00_2 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 25 73 3a 38 30 2f 68 74 74 70 3a 2f 2f 25 73 } //1 Referer: http://%s:80/http://%s
		$a_00_3 = {25 63 25 63 25 63 25 63 25 63 2e 65 78 65 } //1 %c%c%c%c%c.exe
		$a_00_4 = {3a 5c 77 69 6e 64 6f 77 73 2e 42 41 4b } //1 :\windows.BAK
		$a_00_5 = {48 6f 73 74 3a 20 25 73 3a 25 64 } //1 Host: %s:%d
		$a_00_6 = {23 30 25 73 21 } //1 #0%s!
		$a_00_7 = {77 65 6e 68 75 78 69 75 } //1 wenhuxiu
		$a_00_8 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //1 SeShutdownPrivilege
		$a_00_9 = {5c 73 76 63 68 63 73 74 2e 65 78 65 } //1 \svchcst.exe
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=8
 
}