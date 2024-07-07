
rule TrojanDropper_Win32_Agent_FV{
	meta:
		description = "TrojanDropper:Win32/Agent.FV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {fe 10 19 5c cc d4 b1 a6 cc d8 c2 f4 2e 6c 6e 6b 00 fe 81 11 5c 54 61 6f 42 61 6f 5c 74 61 6f 62 61 6f 2e 68 74 6d 6c 00 fe 81 11 5c 54 } //1
		$a_01_1 = {5c 68 70 73 65 74 2e 65 78 65 22 20 2f 73 70 2d 20 2f 76 65 72 79 73 69 6c 65 6e 74 00 fd 99 80 5c 6e 6f 64 65 70 61 64 2e 65 78 65 00 fd 9a 80 5c 6e 73 45 78 65 63 2e 64 6c 6c 00 fe 81 11 5c 54 61 6f 42 61 6f 5c 62 61 69 64 75 53 65 74 75 70 2e 62 61 74 } //1
		$a_01_2 = {5c 54 61 6f 42 61 6f 5c 42 61 69 64 75 2d 54 6f 6f 6c 62 61 72 2e 65 78 65 00 fe 81 11 5c 54 61 6f 42 61 6f 5c 69 6e 66 6f 2e 64 65 73 63 00 fe 81 11 5c 54 61 6f 42 61 6f 5c 73 6f 67 6f 75 5f 70 69 6e 79 69 6e 5f 6d 69 6e 69 5f 35 32 35 34 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}