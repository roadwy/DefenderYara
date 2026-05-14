
rule VirTool_Win64_Indiresz_A{
	meta:
		description = "VirTool:Win64/Indiresz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 05 00 00 00 80 7c 02 fb b8 ?? ?? 49 ff c3 48 ff c0 48 83 f8 40 ?? ?? b9 02 00 00 00 ff ?? ?? ?? ?? ?? 4d 8b c4 ?? ?? ?? ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 33 c0 } //1
		$a_03_1 = {4c 8b d1 8b 05 [0-10] 4c 8b d1 8b 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}