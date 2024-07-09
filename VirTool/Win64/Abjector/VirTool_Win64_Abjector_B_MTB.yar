
rule VirTool_Win64_Abjector_B_MTB{
	meta:
		description = "VirTool:Win64/Abjector.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {65 48 8b 04 25 30 00 00 00 48 85 c0 0f 84 [0-04] 48 8b 48 60 48 85 c9 0f 84 [0-08] 48 8b ?? 18 } //1
		$a_02_1 = {0f b6 0a 84 [0-05] c1 ?? 07 [0-04] 0f be [0-05] 33 ?? 0f b6 ?? 84 } //1
		$a_02_2 = {41 b8 00 30 00 00 [0-03] 44 8d 49 40 [0-05] ?? 0f b7 ?? 14 [0-08] ff } //1
		$a_02_3 = {ba 01 00 00 00 48 03 [0-04] 44 8b c2 [0-03] ff d0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}