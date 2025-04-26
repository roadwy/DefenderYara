
rule Backdoor_Win32_IRCbot_SX{
	meta:
		description = "Backdoor:Win32/IRCbot.SX,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 64 64 20 48 4b 4c 4d 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e 20 2f 76 20 72 75 6e 33 32 20 2f 64 20 22 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 33 32 2e 65 78 65 22 20 2f 66 } //1 add HKLM\software\microsoft\windows\currentversion\run /v run32 /d "%windir%\system32\rundl32.exe" /f
		$a_01_1 = {25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 5c 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 } //1 %windir%\system\winlogon.exe
		$a_01_2 = {5b 69 72 63 5d 0d 0a 6a 3d 6a 6f 69 6e 0d 0a 6e 3d 6e 69 63 6b 0d 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}