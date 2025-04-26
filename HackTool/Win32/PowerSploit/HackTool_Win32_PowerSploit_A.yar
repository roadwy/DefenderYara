
rule HackTool_Win32_PowerSploit_A{
	meta:
		description = "HackTool:Win32/PowerSploit.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {0f b7 4a 26 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0 } //1
		$a_01_1 = {e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2 } //1
		$a_01_2 = {50 68 31 8b 6f 87 ff d5 } //1
		$a_01_3 = {bb e0 1d 2a 0a 68 a6 95 bd 9d ff d5 } //1
		$a_01_4 = {bb 47 13 72 6f 6a 00 53 ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule HackTool_Win32_PowerSploit_A_2{
	meta:
		description = "HackTool:Win32/PowerSploit.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed } //1
		$a_01_1 = {e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24 08 45 39 d1 75 d8 } //1
		$a_01_2 = {41 ba 31 8b 6f 87 ff d5 } //1
		$a_01_3 = {bb e0 1d 2a 0a 41 ba a6 95 bd 9d ff d5 } //1
		$a_01_4 = {bb 47 13 72 6f 6a 00 59 41 89 da ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}