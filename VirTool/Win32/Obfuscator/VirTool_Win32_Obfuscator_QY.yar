
rule VirTool_Win32_Obfuscator_QY{
	meta:
		description = "VirTool:Win32/Obfuscator.QY,SIGNATURE_TYPE_PEHSTR,64 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4e 6c eb 08 34 6b 04 5b 88 01 41 42 8a 02 3c ce 75 f2 c6 01 00 8b 46 6c c3 } //10
		$a_01_1 = {c7 01 9c 72 7a 82 c7 41 04 61 63 7f 79 c7 41 08 7e 7c 61 73 c7 41 0c 73 8c 71 60 c7 41 10 60 61 7c ce } //1
		$a_01_2 = {c7 02 9c 72 7a 83 c7 42 04 7f 79 7e 7c c7 42 08 61 73 73 8c c7 42 0c 71 60 60 61 66 c7 42 10 7c ce } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}