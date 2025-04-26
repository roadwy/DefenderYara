
rule VirTool_Win32_Injector_AJ{
	meta:
		description = "VirTool:Win32/Injector.AJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 36 0f be 14 02 38 d6 74 08 c1 cb 0d 03 da 40 eb ec } //2
		$a_01_1 = {81 ff 59 bc 4a 6a } //2
		$a_00_2 = {68 55 9a d0 3b } //1
		$a_00_3 = {68 1b c6 46 79 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}