
rule VirTool_Win64_Havokiz_x_MTB{
	meta:
		description = "VirTool:Win64/Havokiz.x!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c1 3e 66 90 02 01 75 ef 48 31 c0 66 8b 41 3c 48 01 c8 48 31 db 66 81 c3 90 01 02 3e 66 3b 18 75 d7 48 90 00 } //7
		$a_01_1 = {48 ff c1 3e 66 3b 19 75 ef 48 31 c0 66 8b 41 3c 48 01 c8 48 31 db 66 81 c3 50 45 3e 66 3b 18 75 d7 48 89 c8 c3 } //7
	condition:
		((#a_03_0  & 1)*7+(#a_01_1  & 1)*7) >=7
 
}