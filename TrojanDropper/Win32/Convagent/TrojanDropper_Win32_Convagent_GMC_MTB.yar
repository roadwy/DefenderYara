
rule TrojanDropper_Win32_Convagent_GMC_MTB{
	meta:
		description = "TrojanDropper:Win32/Convagent.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {3a e9 3b de 27 0c 04 b8 ee 8b 32 d3 10 cd fd 31 07 ad 6a 33 19 58 0a } //05 00 
		$a_01_1 = {4b 31 42 f1 24 5c 4b 29 ec 2b 02 03 2d c6 f2 a8 5c 6c 0a c5 56 29 d1 } //01 00 
		$a_80_2 = {54 4a 70 72 6f 6a 4d 61 69 6e 2e 65 78 65 } //TJprojMain.exe  01 00 
		$a_01_3 = {47 50 72 6f 63 30 49 4e 6b 45 78 69 54 74 } //00 00  GProc0INkExiTt
	condition:
		any of ($a_*)
 
}