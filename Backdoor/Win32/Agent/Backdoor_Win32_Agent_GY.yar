
rule Backdoor_Win32_Agent_GY{
	meta:
		description = "Backdoor:Win32/Agent.GY,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 20 59 6f 75 } //10 Kill You
		$a_01_1 = {43 3a 5c 53 68 61 64 6f 77 2e 65 78 65 } //10 C:\Shadow.exe
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 } //1 cmd.exe /c
		$a_01_3 = {43 72 65 61 74 65 50 69 70 65 } //1 CreatePipe
		$a_01_4 = {25 73 20 53 50 25 64 20 28 42 75 69 6c 64 20 25 64 29 } //1 %s SP%d (Build %d)
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=23
 
}