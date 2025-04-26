
rule Backdoor_Win32_Farfli_GZZ_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 34 2c 6b 78 48 38 } //5 M4,kxH8
		$a_01_1 = {9d 10 fb 22 5a 61 01 29 24 37 4c 10 59 52 3b f0 71 ed } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule Backdoor_Win32_Farfli_GZZ_MTB_2{
	meta:
		description = "Backdoor:Win32/Farfli.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 64 24 00 80 b4 05 ?? ?? ?? ?? d7 40 3d c0 67 0f 00 75 } //10
		$a_01_1 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 75 70 64 61 74 65 2e 65 78 65 } //1 \ProgramData\update.exe
		$a_01_2 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6a 66 64 73 2e 74 78 74 } //1 \ProgramData\jfds.txt
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}