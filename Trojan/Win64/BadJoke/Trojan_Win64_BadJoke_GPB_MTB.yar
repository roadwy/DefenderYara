
rule Trojan_Win64_BadJoke_GPB_MTB{
	meta:
		description = "Trojan:Win64/BadJoke.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5f 63 6c 65 61 6e 75 70 25 64 } //1 _cleanup%d
		$a_81_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 49 6e 73 74 61 6c 6c 48 69 6e 66 53 65 63 74 69 6f 6e 20 25 73 20 31 32 38 20 25 73 } //1 rundll32.exe %s,InstallHinfSection %s 128 %s
		$a_81_2 = {43 6f 6d 6d 61 6e 64 2e 63 6f 6d 20 2f 63 20 25 73 } //1 Command.com /c %s
		$a_81_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_81_4 = {63 6d 64 20 2f 63 20 22 64 61 6e 67 65 72 6f 75 73 2e 62 61 74 22 } //1 cmd /c "dangerous.bat"
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}