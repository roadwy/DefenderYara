
rule VirTool_Win64_GoDonutz_A_MTB{
	meta:
		description = "VirTool:Win64/GoDonutz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {48 83 ec 20 48 89 6c 24 18 48 8d 90 01 03 48 89 44 24 28 48 89 4c 24 10 66 90 01 01 e8 90 01 04 48 85 db 74 0c 90 00 } //01 00 
		$a_02_1 = {48 83 ec 58 48 89 6c 24 50 48 8d 90 01 03 48 89 4c 24 70 48 89 44 24 60 48 89 5c 24 68 48 8d 90 01 02 eb 03 48 ff ca 48 85 d2 7c 2d 90 00 } //01 00 
		$a_02_2 = {48 89 44 24 60 90 01 01 48 8b 8c 24 80 00 00 00 48 8b 51 08 48 2b 51 18 48 89 54 24 40 bb e8 ff ff ff e8 90 00 } //01 00 
		$a_02_3 = {4d 89 df 49 f7 db 49 c1 fb 3f 41 81 e3 40 02 00 00 4d 8d 90 01 02 4c 8d 90 01 05 4c 89 e0 bb 10 00 00 00 48 89 d9 48 89 ce 49 89 c8 4d 89 fb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}