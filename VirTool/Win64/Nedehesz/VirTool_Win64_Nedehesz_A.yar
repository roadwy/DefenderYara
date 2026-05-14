
rule VirTool_Win64_Nedehesz_A{
	meta:
		description = "VirTool:Win64/Nedehesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 55 53 57 ?? ?? ?? ?? ?? ?? ?? ?? 48 81 ec 40 07 00 00 48 8b ?? ?? ?? ?? ?? 48 33 c4 48 89 85 20 06 00 00 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 65 48 8b 04 25 60 00 00 00 48 8b 78 18 48 83 c7 20 48 8b 1f 48 3b df } //1
		$a_03_1 = {44 8b 74 31 1c 33 db 8b 7c 31 20 4c 03 f6 44 8b 7c 31 24 48 03 fe 8b 6c 31 18 4c 03 fe 85 ed ?? ?? 66 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}