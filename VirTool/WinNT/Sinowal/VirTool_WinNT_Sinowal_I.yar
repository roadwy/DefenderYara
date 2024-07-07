
rule VirTool_WinNT_Sinowal_I{
	meta:
		description = "VirTool:WinNT/Sinowal.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff 75 10 ff 75 0c ff 55 fc } //1
		$a_03_1 = {89 45 fc 66 c7 45 f0 90 01 02 66 81 45 f0 90 01 02 66 c7 45 f2 90 01 02 66 81 45 f2 90 00 } //1
		$a_01_2 = {8b 40 38 25 ff 0f 00 00 75 } //1
		$a_01_3 = {ff 75 0c 58 ff 50 04 ff 75 08 58 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}