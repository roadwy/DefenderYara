
rule VirTool_Win32_Obfuscator_BZ{
	meta:
		description = "VirTool:Win32/Obfuscator.BZ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {60 6a 00 68 2e 64 6c 6c 68 } //1
		$a_02_1 = {3d 2e 65 78 65 74 90 01 01 3d 2e 45 58 45 74 90 01 01 3d 2e 74 6d 70 74 90 01 01 3d 2e 54 4d 50 90 00 } //1
		$a_00_2 = {68 75 65 6e 63 68 46 72 65 71 68 61 6e 63 65 68 66 6f 72 6d 68 79 50 65 72 68 51 75 65 72 54 } //1 huenchFreqhancehformhyPerhQuerT
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}