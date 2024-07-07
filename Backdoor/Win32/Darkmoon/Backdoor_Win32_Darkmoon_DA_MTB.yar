
rule Backdoor_Win32_Darkmoon_DA_MTB{
	meta:
		description = "Backdoor:Win32/Darkmoon.DA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 66 75 7a 68 75 2e 64 6c 6c } //1 \fuzhu.dll
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c } //1 cmd.exe /c del
		$a_01_2 = {6e 65 74 73 68 20 77 69 6e 73 6f 63 6b 20 72 65 73 65 74 } //1 netsh winsock reset
		$a_01_3 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } //1 BlackMoon RunTime Error
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}