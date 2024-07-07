
rule VirTool_WinNT_Sinowal_F{
	meta:
		description = "VirTool:WinNT/Sinowal.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {b8 38 02 00 c0 9c } //1
		$a_01_1 = {b8 00 04 00 04 9c } //1
		$a_01_2 = {3d 0b 01 00 00 9c } //1
		$a_01_3 = {c7 45 fc a1 eb d9 6e 9c } //1
		$a_03_4 = {c7 45 fc 05 00 00 00 9c 90 02 02 90 04 01 03 50 2d 57 90 00 } //1
		$a_01_5 = {0f 1f 40 00 9d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}