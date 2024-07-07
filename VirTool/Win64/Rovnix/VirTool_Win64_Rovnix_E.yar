
rule VirTool_Win64_Rovnix_E{
	meta:
		description = "VirTool:Win64/Rovnix.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 85 c9 74 08 4d 85 c9 74 0e 49 ff e1 4d 85 c0 74 06 48 8b ca 49 ff e0 b8 0d 00 00 c0 } //1
		$a_01_1 = {40 80 ff 28 74 16 40 80 ff 2a 74 10 40 80 ff 3c 74 0a } //1
		$a_01_2 = {b8 46 4a 00 00 48 83 c3 14 66 39 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}