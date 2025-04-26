
rule VirTool_Win64_Lsassy_B{
	meta:
		description = "VirTool:Win64/Lsassy.B,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 08 00 00 "
		
	strings :
		$a_01_0 = {64 75 6d 70 6d 65 74 68 6f 64 2e 64 6c 6c 69 6e 6a 65 63 74 } //10 dumpmethod.dllinject
		$a_01_1 = {64 75 6d 70 6d 65 74 68 6f 64 2e 70 70 6c 64 75 6d } //10 dumpmethod.ppldum
		$a_01_2 = {64 75 6d 70 6d 65 74 68 6f 64 2e 65 64 72 73 61 6e 64 62 6c 61 73 74 } //10 dumpmethod.edrsandblast
		$a_01_3 = {64 75 6d 70 6d 65 74 68 6f 64 2e 72 64 72 6c 65 61 6b 64 69 61 67 } //5 dumpmethod.rdrleakdiag
		$a_01_4 = {64 75 6d 70 6d 65 74 68 6f 64 2e 73 71 6c 64 75 6d 70 65 72 } //5 dumpmethod.sqldumper
		$a_01_5 = {6d 69 6e 69 64 75 6d 70 2e 73 74 72 65 61 6d 73 2e 53 79 73 74 65 6d 4d 65 6d 6f 72 79 49 6e 66 6f 53 74 72 65 61 6d } //1 minidump.streams.SystemMemoryInfoStream
		$a_01_6 = {6d 69 6e 69 64 75 6d 70 2e 73 74 72 65 61 6d 73 2e 54 6f 6b 65 6e 53 74 72 65 61 6d } //1 minidump.streams.TokenStream
		$a_01_7 = {6d 69 6e 69 64 75 6d 70 2e 6d 69 6e 69 64 75 6d 70 66 69 6c 65 } //1 minidump.minidumpfile
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=27
 
}