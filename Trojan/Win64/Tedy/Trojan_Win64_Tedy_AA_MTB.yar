
rule Trojan_Win64_Tedy_AA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_81_0 = {5c 5c 2e 5c 70 69 70 65 5c 50 61 79 6c 6f 61 64 50 69 70 65 5f 25 6c 75 } //30 \\.\pipe\PayloadPipe_%lu
		$a_01_1 = {63 6f 6e 66 69 67 5f 67 65 74 5f 62 72 6f 77 73 65 72 5f 63 6f 6e 66 69 67 } //20 config_get_browser_config
		$a_01_2 = {7b 22 64 6f 6d 61 69 6e 22 3a 22 25 73 22 2c 22 6e 61 6d 65 22 3a 22 25 73 22 2c 22 76 61 6c 75 65 22 3a 22 25 73 22 2c 22 70 61 74 68 22 3a 22 25 73 22 2c 22 65 78 70 69 72 65 73 22 3a 25 6c 6c 64 2c 22 73 65 63 75 72 65 22 3a 25 73 2c 22 68 74 74 70 4f 6e 6c 79 22 3a 25 73 2c 22 73 61 6d 65 53 69 74 65 22 3a 22 25 73 22 7d } //10 {"domain":"%s","name":"%s","value":"%s","path":"%s","expires":%lld,"secure":%s,"httpOnly":%s,"sameSite":"%s"}
	condition:
		((#a_81_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}
rule Trojan_Win64_Tedy_AA_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 45 42 55 47 3a 20 57 68 61 74 20 64 6f 20 79 6f 75 20 74 68 69 6e 6b 20 79 6f 75 27 72 65 20 64 6f 69 6e 67 20 75 73 65 72 } //10 DEBUG: What do you think you're doing user
		$a_01_1 = {73 68 75 74 64 6f 77 6e 20 2f 73 20 2f 74 20 36 30 20 2f 63 20 22 57 69 6e 64 6f 77 73 20 77 69 6c 6c 20 73 68 75 74 64 6f 77 6e 20 69 6e 20 61 20 6d 69 6e 75 74 65 } //20 shutdown /s /t 60 /c "Windows will shutdown in a minute
		$a_01_2 = {63 6d 64 20 2f 63 20 73 74 61 72 74 20 2f 6d 69 6e 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 49 6e 76 6f 6b 65 2d 43 69 6d 4d 65 74 68 6f 64 20 2d 43 6c 61 73 73 4e 61 6d 65 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 20 2d 4d 65 74 68 6f 64 4e 61 6d 65 20 43 72 65 61 74 65 20 2d 41 72 67 75 6d 65 6e 74 73 20 40 7b 43 6f 6d 6d 61 6e 64 4c 69 6e 65 20 3d 20 27 } //30 cmd /c start /min powershell -Command Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = '
		$a_01_3 = {57 69 6e 64 6f 77 73 20 45 78 65 63 75 74 61 62 6c 65 20 48 65 6c 70 65 72 20 4d 6f 64 75 6c 65 20 54 61 73 6b } //40 Windows Executable Helper Module Task
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}