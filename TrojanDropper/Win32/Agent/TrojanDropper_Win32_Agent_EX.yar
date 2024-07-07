
rule TrojanDropper_Win32_Agent_EX{
	meta:
		description = "TrojanDropper:Win32/Agent.EX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {83 c3 f6 6a 02 6a 00 53 56 e8 90 01 04 6a 00 90 00 } //2
		$a_00_1 = {8a 54 3a ff 80 f2 78 e8 } //2
		$a_02_2 = {83 fe 04 0f 87 bc 00 00 00 ff 24 b5 90 01 03 00 90 00 } //2
		$a_00_3 = {6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 33 00 36 00 30 00 53 00 61 00 66 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2+(#a_00_3  & 1)*2) >=4
 
}