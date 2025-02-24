
rule VirTool_Win64_Shloader_A{
	meta:
		description = "VirTool:Win64/Shloader.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 0d 1a 15 00 00 48 89 15 17 15 00 00 c3 } //1
		$a_01_1 = {48 8b c1 4c 8b d0 8b 05 06 15 00 00 ff 25 04 15 00 00 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}