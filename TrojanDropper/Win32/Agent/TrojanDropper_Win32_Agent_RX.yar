
rule TrojanDropper_Win32_Agent_RX{
	meta:
		description = "TrojanDropper:Win32/Agent.RX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 f2 33 8d 84 24 ?? ?? 00 00 88 94 24 ?? ?? 00 00 8d ?? 01 } //1
		$a_01_1 = {8a 4c 03 01 33 d2 80 f9 5a 0f 94 c2 33 c9 80 3c 18 4d } //1
		$a_00_2 = {64 65 6c 20 25 73 0a 69 66 20 65 78 69 73 74 20 25 73 20 67 6f 74 6f 20 74 72 79 0a 64 65 6c 20 25 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}