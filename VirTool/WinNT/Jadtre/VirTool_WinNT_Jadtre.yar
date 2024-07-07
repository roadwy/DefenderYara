
rule VirTool_WinNT_Jadtre{
	meta:
		description = "VirTool:WinNT/Jadtre,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 e9 43 25 22 00 0f 84 90 01 04 83 e9 49 0f 84 90 01 04 81 e9 d4 00 00 00 90 00 } //1
		$a_01_1 = {0f be c0 c1 ca 07 03 d0 41 8a 01 84 c0 75 f1 } //1
		$a_03_2 = {81 38 8b ff 55 8b 75 90 01 01 81 78 01 ff 55 8b ec 75 90 01 01 83 c0 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}