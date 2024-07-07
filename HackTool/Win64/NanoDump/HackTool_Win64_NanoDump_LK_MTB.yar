
rule HackTool_Win64_NanoDump_LK_MTB{
	meta:
		description = "HackTool:Win64/NanoDump.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 01 d0 0f b7 00 66 89 45 f6 0f b7 45 f6 8b 55 f8 c1 ca 08 01 d0 31 45 f8 8b 55 fc 48 8b 45 10 48 01 d0 0f b6 00 84 c0 75 c7 } //1
		$a_01_1 = {48 8b 45 d0 0f b6 08 48 8b 55 b8 8b 45 f4 48 98 48 01 d0 89 ca 88 10 48 83 45 f8 02 83 45 f4 01 } //1
		$a_01_2 = {88 05 7e 8c 08 00 8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 0f b6 4d fb 8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}