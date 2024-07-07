
rule Trojan_Win32_Killfiles_CG{
	meta:
		description = "Trojan:Win32/Killfiles.CG,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 63 68 6f 20 57 41 52 4e 49 4e 47 20 56 49 52 55 53 20 48 41 53 20 42 45 45 4e 20 44 45 54 45 43 54 45 44 } //1 echo WARNING VIRUS HAS BEEN DETECTED
		$a_01_1 = {64 65 6c 20 25 73 79 73 74 65 6d 64 72 69 76 65 25 5c 2a 2e 2a 20 2f 73 20 2f 66 20 2f 71 } //1 del %systemdrive%\*.* /s /f /q
		$a_01_2 = {73 74 61 72 74 20 25 77 69 6e 64 69 72 25 5c 53 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 75 73 65 72 33 32 2e 64 6c 6c 2c 20 4c 6f 63 6b 57 6f 72 6b 53 74 61 74 69 6f 6e } //1 start %windir%\System32\rundll32.exe user32.dll, LockWorkStation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}