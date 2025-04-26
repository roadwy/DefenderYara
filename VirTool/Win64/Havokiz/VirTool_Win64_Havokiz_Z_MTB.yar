
rule VirTool_Win64_Havokiz_Z_MTB{
	meta:
		description = "VirTool:Win64/Havokiz.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 ff c1 3e 66 3b 19 75 ef 48 31 c0 66 8b 41 ?? 48 01 c8 48 31 db 66 81 c3 ?? ?? 3e 66 3b 18 75 d7 48 89 c8 c3 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}