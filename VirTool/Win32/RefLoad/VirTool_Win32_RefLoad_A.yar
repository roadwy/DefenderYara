
rule VirTool_Win32_RefLoad_A{
	meta:
		description = "VirTool:Win32/RefLoad.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_03_0 = {4d 5a e8 00 00 00 00 5b 52 45 55 8b ec 81 c3 ?? ?? ?? ?? ff d3 c9 c3 } //5
		$a_01_1 = {5b bc 4a 6a } //1
		$a_01_2 = {5d 68 fa 3c } //1
		$a_01_3 = {8e 4e 0e ec } //1
		$a_01_4 = {aa fc 0d 7c } //1
		$a_01_5 = {1b c6 46 79 } //1
		$a_01_6 = {b8 0a 4c 53 } //1
		$a_01_7 = {54 ca af 91 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}