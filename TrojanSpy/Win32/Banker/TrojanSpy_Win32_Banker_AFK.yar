
rule TrojanSpy_Win32_Banker_AFK{
	meta:
		description = "TrojanSpy:Win32/Banker.AFK,SIGNATURE_TYPE_PEHSTR_EXT,ffffffa0 00 ffffff8c 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 71 7a 36 4c 35 54 31 4b 61 4c 53 4a 4b 62 33 4b 61 7a 4a 4a 71 50 4b 4e 35 54 39 4a 61 48 46 4c 72 44 53 47 72 4c 49 4b 61 4c 45 4c 35 50 35 4b 62 44 39 4a 71 76 53 4b 62 4c 45 } //100 Kqz6L5T1KaLSJKb3KazJJqPKN5T9JaHFLrDSGrLIKaLEL5P5KbD9JqvSKbLE
		$a_01_1 = {4a 36 35 5a 4f 73 4c 70 53 6d } //20 J65ZOsLpSm
		$a_01_2 = {63 3a 5c 50 72 6f 67 72 61 6d 4c 6f 67 5c 77 73 62 73 6c 74 66 79 2e 65 78 65 } //20 c:\ProgramLog\wsbsltfy.exe
		$a_01_3 = {5b 62 62 2e 63 6f 6d 2e 62 72 5d } //20 [bb.com.br]
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*20+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20) >=140
 
}