
rule Backdoor_Win32_NetWiredRC_C_Lowfi{
	meta:
		description = "Backdoor:Win32/NetWiredRC.C!Lowfi,SIGNATURE_TYPE_PEHSTR,ffffffc8 00 ffffffc8 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 1b 8a 44 0f ff 3c 7a 75 d3 4a 8a 04 17 fe c0 88 04 17 3c 7b 75 b0 c6 04 17 41 eb ed 89 fb 89 f7 b9 21 01 00 00 31 d2 ac } //1
		$a_01_1 = {75 7a 8a 04 17 fe c0 88 04 17 29 c0 83 c0 06 89 c1 53 56 8a 44 0e ff 32 44 0f ff 5e 5b 3a 44 0b ff 75 04 e2 ec } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=200
 
}