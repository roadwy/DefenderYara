
rule VirTool_Win64_Threadesz_A{
	meta:
		description = "VirTool:Win64/Threadesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b d2 48 8b 02 4c 8b 5a 10 49 83 fb 04 ?? ?? 49 83 fb 00 ?? ?? 49 8b 4a 18 49 83 fb 01 ?? ?? 49 8b 52 20 49 83 fb 02 ?? ?? 4d 8b 42 28 49 83 fb 03 ?? ?? 4d 8b 4a 30 49 83 fb 04 } //1
		$a_03_1 = {4d 8b 52 08 53 48 83 ec 20 41 52 48 8b ?? ?? ?? ?? ?? 48 83 c3 08 ?? ?? 48 c7 c0 00 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}