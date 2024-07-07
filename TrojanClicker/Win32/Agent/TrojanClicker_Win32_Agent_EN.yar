
rule TrojanClicker_Win32_Agent_EN{
	meta:
		description = "TrojanClicker:Win32/Agent.EN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 17 8d 8c 24 90 01 02 00 00 51 6a 00 ff 90 00 } //1
		$a_00_1 = {4e 65 77 53 74 61 72 74 5c 41 44 53 43 75 74 5f 53 69 6e 67 6c 65 51 51 5c 72 65 6c 65 61 73 65 5c 41 44 53 43 75 74 2e 70 64 62 } //1 NewStart\ADSCut_SingleQQ\release\ADSCut.pdb
		$a_00_2 = {51 51 d3 b0 d2 f4 c9 fd bc b6 b0 fc a3 ac c7 eb cf c2 d4 d8 b0 b2 d7 b0 a1 a3 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}