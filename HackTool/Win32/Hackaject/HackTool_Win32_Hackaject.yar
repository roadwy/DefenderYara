
rule HackTool_Win32_Hackaject{
	meta:
		description = "HackTool:Win32/Hackaject,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_02_0 = {5c 00 73 00 69 00 6d 00 75 00 6c 00 61 00 73 00 69 00 90 02 20 62 00 69 00 73 00 61 00 2e 00 76 00 62 00 70 00 90 00 } //02 00 
		$a_02_1 = {5c 00 69 00 6e 00 6a 00 65 00 90 02 20 62 00 69 00 73 00 61 00 2e 00 76 00 62 00 70 00 90 00 } //02 00 
		$a_00_2 = {61 00 64 00 66 00 2e 00 6c 00 79 00 } //01 00  adf.ly
		$a_00_3 = {5c 52 65 6c 65 61 73 65 5c 50 6f 69 6e 74 42 6c 61 6e 6b 2e 70 64 62 } //01 00  \Release\PointBlank.pdb
		$a_00_4 = {50 00 6f 00 69 00 6e 00 74 00 42 00 6c 00 61 00 6e 00 6b 00 2e 00 65 00 78 00 65 00 } //00 00  PointBlank.exe
	condition:
		any of ($a_*)
 
}