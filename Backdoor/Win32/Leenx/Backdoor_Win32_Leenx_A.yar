
rule Backdoor_Win32_Leenx_A{
	meta:
		description = "Backdoor:Win32/Leenx.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 00 00 00 73 76 63 68 6f 73 74 2e 65 78 65 } //1
		$a_02_1 = {33 c0 8a 88 90 01 04 80 f1 90 01 01 88 8c 05 90 01 04 40 3d 90 01 02 00 00 7c 90 00 } //1
		$a_02_2 = {56 8b ff b9 90 01 04 8d b5 90 01 04 8b fb f3 a5 8b ff 8d 45 90 01 01 50 6a 00 6a 00 53 6a 00 6a 00 ff 15 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}