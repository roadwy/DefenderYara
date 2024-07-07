
rule VirTool_Win64_GMimitz_A_MTB{
	meta:
		description = "VirTool:Win64/GMimitz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {48 83 ec 30 48 89 6c 24 28 48 8d 90 01 03 48 8b 15 51 84 31 00 48 8b 35 52 84 31 00 31 c0 eb 0f 90 00 } //1
		$a_00_1 = {44 0f b6 04 02 4c 8b 0d 46 84 31 00 48 8b 0d 47 84 31 00 48 39 c8 72 d4 } //1
		$a_00_2 = {48 89 44 24 20 31 db 31 c9 48 89 cf e8 } //1
		$a_00_3 = {46 0f b6 14 08 45 31 c2 45 88 14 01 48 ff c0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}