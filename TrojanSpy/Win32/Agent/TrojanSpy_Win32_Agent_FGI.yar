
rule TrojanSpy_Win32_Agent_FGI{
	meta:
		description = "TrojanSpy:Win32/Agent.FGI,SIGNATURE_TYPE_PEHSTR,06 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 56 56 68 cc 00 00 00 ff 35 f4 63 40 00 bd e8 67 40 00 bb 44 63 40 00 6a 1a 6a 1c 6a 22 6a 04 68 00 00 00 50 55 53 56 ff d7 a3 20 64 40 00 } //5
		$a_01_1 = {68 00 00 88 00 68 68 63 40 00 68 60 63 40 00 56 ff d7 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=5
 
}