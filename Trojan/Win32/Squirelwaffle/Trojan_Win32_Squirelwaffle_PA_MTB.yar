
rule Trojan_Win32_Squirelwaffle_PA_MTB{
	meta:
		description = "Trojan:Win32/Squirelwaffle.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 20 2f 69 20 2f 6d 69 6e 20 2f 62 20 73 74 61 72 74 20 2f 69 20 2f 6d 69 6e 20 2f 62 20 73 74 61 72 74 20 2f 69 20 2f 6d 69 6e 20 2f 62 } //1 start /i /min /b start /i /min /b start /i /min /b
		$a_01_1 = {5c 44 6c 6c 31 2e 70 64 62 } //1 \Dll1.pdb
		$a_03_2 = {33 d2 c7 45 dc 00 00 00 00 8b c7 c7 45 e0 90 01 01 00 00 00 f7 75 30 83 7d 1c 90 01 01 8d 4d 90 01 01 8d 45 90 01 01 c6 45 90 01 01 00 0f 43 4d 90 01 01 83 7d 34 90 01 01 0f 43 45 20 8a 04 10 32 04 39 8d 4d cc 0f b6 c0 50 6a 01 e8 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}