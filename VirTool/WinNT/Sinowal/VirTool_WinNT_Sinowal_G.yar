
rule VirTool_WinNT_Sinowal_G{
	meta:
		description = "VirTool:WinNT/Sinowal.G,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {83 ff 00 5f 0f 85 } //1
		$a_01_1 = {83 fb 00 5b 0f 85 } //1
		$a_01_2 = {83 fe 00 5e 0f 85 } //1
		$a_03_3 = {bb 00 00 00 00 81 c3 ?? ?? ?? ?? 53 } //1
		$a_03_4 = {b9 00 00 00 00 81 c1 ?? ?? ?? ?? 51 } //1
		$a_03_5 = {24 83 c4 04 33 f6 81 c6 90 09 02 00 8b } //1
		$a_03_6 = {38 02 00 c0 (eb|e9) 90 09 05 00 [b8-bf] } //6
		$a_01_7 = {8b 45 08 89 45 fc 66 c7 45 f0 18 00 66 c7 45 f2 1a 00 c7 45 f4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*6+(#a_01_7  & 1)*1) >=7
 
}