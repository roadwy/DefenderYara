
rule HackTool_Win64_Darkside_AA_MTB{
	meta:
		description = "HackTool:Win64/Darkside.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 53 65 72 76 69 63 65 20 57 48 45 52 45 20 4e 61 6d 65 20 3d 20 27 57 69 6e 44 65 66 65 6e 64 27 } //1 SELECT * FROM Win32_Service WHERE Name = 'WinDefend'
		$a_01_1 = {44 00 61 00 72 00 6b 00 53 00 69 00 64 00 65 00 2e 00 65 00 78 00 65 00 20 00 2d 00 6b 00 69 00 6c 00 6c 00 64 00 65 00 66 00 } //1 DarkSide.exe -killdef
		$a_01_2 = {41 00 74 00 74 00 65 00 6d 00 70 00 74 00 20 00 74 00 6f 00 20 00 6b 00 69 00 6c 00 6c 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 } //1 Attempt to kill Windows Defender
		$a_01_3 = {44 61 72 6b 73 69 64 65 2e 70 64 62 } //1 Darkside.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}