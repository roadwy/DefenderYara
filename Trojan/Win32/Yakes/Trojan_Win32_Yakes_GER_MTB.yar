
rule Trojan_Win32_Yakes_GER_MTB{
	meta:
		description = "Trojan:Win32/Yakes.GER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 61 64 76 70 61 63 6b 2e 64 6c 6c 2c 44 65 6c 4e 6f 64 65 52 75 6e 44 4c 4c 33 32 } //1 rundll32.exe %sadvpack.dll,DelNodeRunDLL32
		$a_01_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 49 6e 73 74 61 6c 6c 48 69 6e 66 53 65 63 74 69 6f 6e 20 25 73 20 31 32 38 20 25 73 } //1 rundll32.exe %s,InstallHinfSection %s 128 %s
		$a_01_2 = {63 6d 64 20 2f 63 20 69 2e 62 61 74 } //1 cmd /c i.bat
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_4 = {63 75 72 6c 20 2d 4c 20 2d 6f 20 64 2e 65 78 65 20 69 6c 32 64 2e 63 63 } //1 curl -L -o d.exe il2d.cc
		$a_01_5 = {77 65 78 74 72 61 63 74 5f 63 6c 65 61 6e 75 70 25 64 } //1 wextract_cleanup%d
		$a_01_6 = {43 6f 6d 6d 61 6e 64 2e 63 6f 6d 20 2f 63 20 25 73 } //1 Command.com /c %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}