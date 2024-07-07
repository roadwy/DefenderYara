
rule VirTool_Win64_Radkt_A_MTB{
	meta:
		description = "VirTool:Win64/Radkt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 20 90 02 14 85 c0 90 01 02 8b d0 90 02 17 48 8b 4c 24 38 90 02 17 48 8b 01 90 01 03 85 c0 90 01 02 8b d0 90 02 17 8b 44 24 40 85 c0 90 00 } //1
		$a_03_1 = {48 8b 74 24 30 85 c0 90 01 06 8b f8 48 8b 4b e8 90 01 06 48 8b 4b f0 90 01 06 48 8b 0b 90 02 10 48 83 ef 01 90 01 02 48 8b ce 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}