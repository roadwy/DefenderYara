
rule VirTool_WinNT_Sinowal_D{
	meta:
		description = "VirTool:WinNT/Sinowal.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 f6 9c 50 } //1
		$a_01_1 = {83 7c 24 0c 05 9c 50 } //1
		$a_01_2 = {68 70 53 74 75 ff 74 24 08 6a 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}