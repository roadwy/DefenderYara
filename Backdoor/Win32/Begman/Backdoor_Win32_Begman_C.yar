
rule Backdoor_Win32_Begman_C{
	meta:
		description = "Backdoor:Win32/Begman.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {10 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 } //1
		$a_03_1 = {56 42 4f 58 [0-0f] 51 45 4d 55 [0-0a] 55 8b ec 6a 00 6a 00 53 56 } //1
		$a_01_2 = {65 78 70 61 6e 64 20 2d 72 20 } //1 expand -r 
		$a_01_3 = {77 75 73 61 2e 65 78 65 } //1 wusa.exe
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}