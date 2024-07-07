
rule VirTool_Win64_Tknmp_MTB{
	meta:
		description = "VirTool:Win64/Tknmp!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {65 48 8b 04 25 88 01 00 00 48 8b 80 b8 00 00 00 48 89 c3 48 8b 9b 90 01 01 02 00 00 48 81 eb 90 01 01 02 00 00 48 8b 8b e8 02 00 00 48 83 f9 04 75 e5 48 8b 8b 90 01 01 03 00 00 80 e1 f0 48 89 88 90 01 01 03 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}