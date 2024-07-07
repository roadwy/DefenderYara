
rule VirTool_Win64_Modlesz_A_MTB{
	meta:
		description = "VirTool:Win64/Modlesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 8b d8 ff 15 90 01 04 48 63 4b 3c 8b 5c 19 28 48 8d 0d 90 01 04 8b d3 e8 47 90 01 03 48 03 de 48 8d 90 01 05 48 90 00 } //1
		$a_03_1 = {41 b9 00 30 00 00 c7 44 24 20 04 00 00 00 48 63 f0 33 d2 4c 8b c6 48 8b cf ff 15 90 01 04 48 8b d8 48 85 c0 75 90 00 } //1
		$a_03_2 = {48 8b c8 48 8d 90 01 05 ff 15 90 01 04 48 85 c0 75 90 00 } //1
		$a_03_3 = {4c 89 74 24 58 48 8d 0d 90 01 04 e8 95 90 01 03 45 33 f6 4c 8d 05 90 01 04 4c 8b ce 4c 89 74 24 20 48 8b d3 48 8b cf ff 15 90 01 04 85 c0 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}