
rule Backdoor_Win32_Bittaru_A{
	meta:
		description = "Backdoor:Win32/Bittaru.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 53 4f 4c 43 75 0f c7 05 [0-08] e9 be 00 00 00 3d 3a 44 4d 43 } //2
		$a_03_1 = {3d 44 48 4b 4c 75 09 e8 ?? ?? ?? ?? 0b c0 75 2d 3d 53 4c 53 50 } //2
		$a_01_2 = {3d 44 4c 50 55 75 } //1 =DLPUu
		$a_01_3 = {3d 4b 4f 4f 4c 75 10 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}