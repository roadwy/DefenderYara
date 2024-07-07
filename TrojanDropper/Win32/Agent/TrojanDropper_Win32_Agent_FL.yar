
rule TrojanDropper_Win32_Agent_FL{
	meta:
		description = "TrojanDropper:Win32/Agent.FL,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 4f 20 6a 02 ff 74 24 10 6a 00 51 ff d0 } //1
		$a_01_1 = {c6 45 e8 33 c6 45 e9 36 c6 45 ea 30 c6 45 eb 74 c6 45 ec 72 } //2
		$a_01_2 = {57 69 6e 64 6f 77 73 20 ce c4 bc fe b1 a3 bb a4 } //1
		$a_01_3 = {25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 64 61 74 61 2e 64 6c 6c } //1 %ProgramFiles%\data.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}