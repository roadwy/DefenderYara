
rule Trojan_Win32_MarsStealer_MA_MTB{
	meta:
		description = "Trojan:Win32/MarsStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 8b 4c 24 10 c1 e8 05 03 44 24 28 33 cb c7 05 90 01 08 c7 05 90 01 08 89 44 24 18 89 4c 24 10 8b 44 24 18 31 44 24 10 2b 74 24 10 81 c7 90 01 04 4d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_MarsStealer_MA_MTB_2{
	meta:
		description = "Trojan:Win32/MarsStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 a3 90 01 04 68 90 0a 19 00 8b ec 68 90 01 04 e8 90 02 15 e8 90 01 04 83 c4 04 a3 90 01 05 8b 44 24 04 05 1a 58 01 00 ff d0 90 00 } //10
		$a_00_1 = {8b ec c7 05 6c 73 41 00 50 30 41 00 c7 05 f0 71 41 00 68 30 41 00 c7 05 68 74 41 00 78 30 41 00 c7 05 c0 77 41 00 88 30 41 00 c7 05 f8 70 41 00 94 30 41 00 c7 05 48 76 41 00 a4 30 41 00 c7 05 04 77 41 00 b0 30 41 00 c7 05 34 73 41 00 c0 30 41 00 c7 05 ac 75 41 00 c8 30 41 00 c7 05 a4 74 41 00 e0 30 41 00 } //10
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}