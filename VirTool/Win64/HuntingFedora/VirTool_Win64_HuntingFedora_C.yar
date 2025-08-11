
rule VirTool_Win64_HuntingFedora_C{
	meta:
		description = "VirTool:Win64/HuntingFedora.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {4c 89 ea 68 01 01 00 00 59 41 ba ?? ?? ?? ?? ff d5 50 50 4d 31 c9 4d 31 c0 48 ff c0 48 89 c2 48 ff c0 48 89 c1 41 ba } //1
		$a_03_1 = {4c 89 e2 48 89 f9 41 ba ?? ?? ?? ?? ff d5 48 81 c4 40 02 00 00 49 b8 63 ?? ?? ?? ?? ?? ?? ?? 41 50 41 50 48 89 e2 57 57 57 4d 31 c0 6a 0d } //1
		$a_03_2 = {4d 89 c1 4c 89 c1 41 ba ?? ?? ?? ?? ff d5 48 31 d2 48 ff ca 8b 0e 41 ba ?? ?? ?? ?? ff d5 bb f0 b5 a2 56 41 ba } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}