
rule TrojanDropper_Win32_Agent_FO{
	meta:
		description = "TrojanDropper:Win32/Agent.FO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f 31 2b c3 eb 05 68 f0 0f c7 c8 1b d1 85 d2 75 f6 } //1
		$a_01_1 = {7c 02 eb 02 74 fc 7d 02 eb 02 75 fc 7c 05 74 05 75 03 e8 74 f9 } //1
		$a_01_2 = {66 9c 73 05 74 08 75 06 e8 e8 02 00 00 00 72 f4 83 c4 04 66 9d 78 03 79 01 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}