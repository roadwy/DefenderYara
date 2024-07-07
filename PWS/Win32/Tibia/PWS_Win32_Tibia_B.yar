
rule PWS_Win32_Tibia_B{
	meta:
		description = "PWS:Win32/Tibia.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {61 64 64 20 68 6b 6c 6d 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e 20 2f 76 20 57 69 6e 64 6f 77 73 20 2f 64 } //1 add hklm\software\microsoft\windows\currentversion\run /v Windows /d
		$a_01_1 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_01_2 = {54 69 62 69 61 43 6c 69 65 6e 74 } //1 TibiaClient
		$a_01_3 = {26 6e 6f 74 61 74 6b 61 3d } //1 &notatka=
		$a_01_4 = {63 3a 5c 78 2e 65 78 65 } //1 c:\x.exe
		$a_01_5 = {26 6e 75 6d 65 72 3d } //1 &numer=
		$a_01_6 = {26 70 61 73 73 3d } //1 &pass=
		$a_01_7 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}