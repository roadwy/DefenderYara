
rule TrojanSpy_Win32_Bafi_A{
	meta:
		description = "TrojanSpy:Win32/Bafi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 00 43 00 4c 00 49 00 43 00 4b 00 44 00 42 00 4c 00 00 00 } //1
		$a_01_1 = {46 49 44 55 43 49 41 2e 44 45 00 00 } //1
		$a_01_2 = {fa 02 6f dc 3f 10 c7 b9 1e a0 c6 85 94 4d 5e 32 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}