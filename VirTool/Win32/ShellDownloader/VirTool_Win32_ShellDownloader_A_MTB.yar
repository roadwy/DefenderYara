
rule VirTool_Win32_ShellDownloader_A_MTB{
	meta:
		description = "VirTool:Win32/ShellDownloader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {51 0f 43 85 90 01 04 8d 8d 90 01 04 03 c6 50 e8 90 01 04 83 8d e8 90 01 03 08 8d 85 90 01 04 83 bd 90 01 04 10 6a 10 0f 43 85 90 01 04 6a 00 50 ff 15 90 00 } //1
		$a_03_1 = {6a 40 68 00 10 00 00 68 00 20 00 00 6a 00 ff 15 90 01 04 8b f0 8d 85 90 01 04 68 00 20 00 00 50 56 e8 90 01 04 83 c4 0c 90 00 } //1
		$a_03_2 = {b8 02 00 00 00 66 89 85 80 bf ff ff 8b 46 0c 6a 10 8b 00 8b 00 89 85 84 bf ff ff 8d 85 90 01 04 50 57 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}