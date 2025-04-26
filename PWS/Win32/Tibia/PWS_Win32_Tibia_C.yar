
rule PWS_Win32_Tibia_C{
	meta:
		description = "PWS:Win32/Tibia.C,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 0a 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {61 64 64 20 68 6b 6c 6d 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e 20 2f 76 20 6f 72 63 54 6f 42 79 6c 6f 4c 61 74 77 65 20 2f 64 20 } //10 add hklm\software\microsoft\windows\currentversion\run /v orcToByloLatwe /d 
		$a_00_2 = {74 69 62 69 61 63 6c 69 65 6e 74 } //10 tibiaclient
		$a_02_3 = {6a 00 6a 00 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 68 ?? ?? 40 00 8d 45 cc ba 03 00 00 00 e8 ?? ?? ff ff 8b 45 cc e8 ?? ?? ff ff 50 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 } //10
		$a_00_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 44 72 69 76 65 72 73 5c 45 74 63 5c 48 6f 73 74 73 } //1 C:\WINDOWS\system32\Drivers\Etc\Hosts
		$a_02_5 = {68 74 74 70 3a 2f 2f [0-10] 2f 76 69 70 2f 64 6f 64 61 6a 2e 70 68 70 3f 6c 6f 67 69 6e 3d } //1
		$a_00_6 = {26 70 61 73 73 3d } //1 &pass=
		$a_00_7 = {26 6e 6f 74 61 74 6b 61 3d } //1 &notatka=
		$a_00_8 = {26 6e 75 6d 65 72 3d } //1 &numer=
		$a_00_9 = {63 3a 5c 78 2e 65 78 65 } //1 c:\x.exe
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*10+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=46
 
}