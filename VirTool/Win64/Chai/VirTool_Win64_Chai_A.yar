
rule VirTool_Win64_Chai_A{
	meta:
		description = "VirTool:Win64/Chai.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b ce ff ?? ?? ?? ?? ?? 48 8b 55 f7 ?? ?? ?? ?? ?? ?? ?? 44 8b c0 ?? ?? ?? ?? ?? 48 8b 55 f7 45 33 c9 45 33 c0 4c 89 7c 24 20 48 8b ce } //1
		$a_01_1 = {48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 53 56 57 48 83 ec 30 48 8b f9 } //1
		$a_03_2 = {48 89 5c 24 38 44 8d 43 50 89 5c 24 30 ?? ?? ?? ?? ?? ?? ?? c7 44 24 28 03 00 00 00 45 33 c9 48 8b c8 48 89 5c 24 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}