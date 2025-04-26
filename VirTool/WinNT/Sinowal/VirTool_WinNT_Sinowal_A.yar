
rule VirTool_WinNT_Sinowal_A{
	meta:
		description = "VirTool:WinNT/Sinowal.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 f6 c7 05 ?? ?? ?? 00 ?? ?? ?? 00 ff 25 } //1
		$a_02_1 = {83 7c 24 0c 05 c7 05 ?? ?? ?? 00 ?? ?? ?? 00 ff 25 } //1
		$a_01_2 = {68 70 53 74 75 ff 74 24 08 6a 00 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}