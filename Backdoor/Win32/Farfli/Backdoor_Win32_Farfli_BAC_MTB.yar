
rule Backdoor_Win32_Farfli_BAC_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 6a 00 6a 00 50 b9 57 37 01 00 81 c6 74 dd 04 00 8b f8 50 6a 00 6a 00 f3 a5 ff 15 } //2
		$a_01_1 = {31 30 33 2e 31 36 33 2e 34 37 2e 32 34 37 } //2 103.163.47.247
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}