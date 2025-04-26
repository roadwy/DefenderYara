
rule VirTool_Win32_Tinmet_A{
	meta:
		description = "VirTool:Win32/Tinmet.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {56 89 75 fc ff d3 a1 ?? ?? ?? ?? 6a 40 68 00 10 00 00 83 c0 05 50 [0-06] ff 15 } //2
		$a_03_1 = {c7 45 fc 80 33 00 00 50 6a 1f 56 ff 15 ?? ?? ?? ?? 53 53 53 53 56 ff 15 ?? ?? ?? ?? 85 c0 75 07 68 ?? ?? ?? ?? eb ?? 6a 40 68 00 10 00 00 68 00 00 40 00 53 ff 15 } //2
		$a_03_2 = {83 c4 0c a3 ?? ?? ?? 00 ff d0 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=5
 
}