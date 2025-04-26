
rule TrojanDropper_Win32_Convagent_GMC_MTB{
	meta:
		description = "TrojanDropper:Win32/Convagent.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a e9 3b de 27 0c 04 b8 ee 8b 32 d3 10 cd fd 31 07 ad 6a 33 19 58 0a } //5
		$a_01_1 = {4b 31 42 f1 24 5c 4b 29 ec 2b 02 03 2d c6 f2 a8 5c 6c 0a c5 56 29 d1 } //5
		$a_80_2 = {54 4a 70 72 6f 6a 4d 61 69 6e 2e 65 78 65 } //TJprojMain.exe  1
		$a_01_3 = {47 50 72 6f 63 30 49 4e 6b 45 78 69 54 74 } //1 GProc0INkExiTt
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}