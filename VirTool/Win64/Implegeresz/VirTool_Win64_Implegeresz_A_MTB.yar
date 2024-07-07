
rule VirTool_Win64_Implegeresz_A_MTB{
	meta:
		description = "VirTool:Win64/Implegeresz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 0d 8e 68 03 00 90 01 07 48 89 05 48 68 03 00 90 01 05 48 8b 0d 74 68 03 00 90 01 07 48 89 05 26 68 03 00 90 01 05 48 8b 0d 5a 68 03 00 90 01 07 48 89 05 04 68 03 00 90 01 05 48 8b 0d 40 68 03 00 90 01 07 48 89 05 e2 67 03 00 90 01 05 48 8b 0d 26 68 03 00 90 01 07 48 89 90 00 } //1
		$a_03_1 = {48 8b 05 5f 13 01 00 48 c1 e6 04 90 01 05 48 03 35 df f3 02 00 48 89 46 08 90 02 18 48 8b 0d c3 f3 02 00 48 89 da 48 89 c5 90 01 05 48 89 c1 90 01 05 48 8b 90 00 } //1
		$a_03_2 = {48 83 ec 48 90 01 07 48 89 cf 48 89 d1 90 01 05 48 89 c6 90 01 05 48 85 c0 48 89 c3 90 01 02 48 8b 00 90 01 09 48 89 ea 48 89 c1 49 89 c1 90 01 05 48 89 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}