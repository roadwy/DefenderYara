
rule Trojan_Win32_Agent_DO{
	meta:
		description = "Trojan:Win32/Agent.DO,SIGNATURE_TYPE_PEHSTR,3d 00 3d 00 08 00 00 "
		
	strings :
		$a_01_0 = {74 69 74 6c 65 20 4c 4f 4c } //10 title LOL
		$a_01_1 = {62 61 74 66 69 6c 65 2e 62 61 74 } //10 batfile.bat
		$a_01_2 = {62 61 74 63 68 66 69 6c 65 2e 62 61 74 } //10 batchfile.bat
		$a_01_3 = {64 65 6c 20 63 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //10 del c:\WINDOWS\system32\drivers\etc\hosts
		$a_01_4 = {63 6f 70 79 20 68 6f 73 74 73 20 63 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //10 copy hosts c:\WINDOWS\system32\drivers\etc\hosts
		$a_01_5 = {3e 3e 25 77 69 6e 64 69 72 25 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //10 >>%windir%\System32\drivers\etc\hosts
		$a_01_6 = {65 63 68 6f 20 37 35 2e 31 32 37 2e 38 33 2e } //1 echo 75.127.83.
		$a_01_7 = {65 63 68 6f 20 37 35 2e 31 32 37 2e 38 35 2e } //1 echo 75.127.85.
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=61
 
}