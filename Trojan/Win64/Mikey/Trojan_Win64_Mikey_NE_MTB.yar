
rule Trojan_Win64_Mikey_NE_MTB{
	meta:
		description = "Trojan:Win64/Mikey.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_81_0 = {73 74 61 72 74 20 63 6d 64 20 2f 43 20 22 43 4f 4c 4f 52 20 43 20 26 26 20 65 63 68 6f 2e 20 4f 75 74 64 61 74 65 64 20 76 65 72 73 69 6f 6e 2c 20 63 6f 6e 74 61 63 74 20 66 61 65 6c 23 32 30 38 31 20 26 26 20 54 49 4d 45 4f 55 54 20 31 30 20 3e 20 6e 75 6c } //2 start cmd /C "COLOR C && echo. Outdated version, contact fael#2081 && TIMEOUT 10 > nul
		$a_81_1 = {78 78 78 78 3f 78 78 78 78 3f 3f 3f 3f 78 78 78 } //1 xxxx?xxxx????xxx
		$a_81_2 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 25 6c 64 25 73 } //1 ----------------%ld%s
		$a_81_3 = {73 65 63 75 72 69 74 79 2e 64 6c 6c } //1 security.dll
		$a_81_4 = {44 65 63 72 79 70 74 4d 65 73 73 61 67 65 } //1 DecryptMessage
		$a_81_5 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 4b 73 44 75 6d 70 65 72 44 72 69 76 65 72 2e 73 79 73 } //1 C:\Windows\KsDumperDriver.sys
		$a_81_6 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 64 6e 53 70 79 } //1 AppData\Local\dnSpy
		$a_81_7 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 } //1 C:\ProgramData\Microsoft\Windows\Start Menu\Programs
		$a_81_8 = {5c 65 78 61 6d 70 6c 65 73 5c 45 78 65 5c } //1 \examples\Exe\
		$a_81_9 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 72 75 6c 65 20 6e 61 6d 65 } //1 netsh advfirewall firewall add rule name
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=11
 
}