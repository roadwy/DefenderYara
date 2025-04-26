
rule Backdoor_Win32_Caphaw_AD{
	meta:
		description = "Backdoor:Win32/Caphaw.AD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 81 c4 cc 00 00 00 50 81 ec c8 00 00 00 83 c4 6c 61 83 c4 3c 58 5d ff e0 ff e1 } //1
		$a_01_1 = {6a 04 68 00 10 00 00 8b 45 f4 50 6a 00 8b 4d 10 ff 51 10 89 45 e0 b8 00 00 00 00 b8 00 00 00 00 83 7d e0 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}