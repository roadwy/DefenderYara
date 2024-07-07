
rule HackTool_AndroidOS_Faceniff_A_MTB{
	meta:
		description = "HackTool:AndroidOS/Faceniff.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {66 61 63 65 6e 69 66 66 2e 70 6f 6e 75 72 79 2e 6e 65 74 } //1 faceniff.ponury.net
		$a_00_1 = {53 74 65 61 6c 74 68 20 6d 6f 64 65 20 69 73 20 6d 75 63 68 20 73 6c 6f 77 65 72 } //1 Stealth mode is much slower
		$a_00_2 = {54 68 69 73 20 70 68 6f 6e 65 20 69 73 20 6e 6f 74 20 72 6f 6f 74 65 64 } //1 This phone is not rooted
		$a_00_3 = {54 72 79 69 6e 67 20 74 6f 20 66 65 74 63 68 20 66 61 63 65 62 6f 6f 6b 20 70 72 6f 66 69 6c 65 20 70 68 6f 74 6f } //1 Trying to fetch facebook profile photo
		$a_00_4 = {61 70 70 6c 69 63 61 74 69 6f 6e 20 6c 6f 63 6b 65 64 } //1 application locked
		$a_00_5 = {74 62 5f 73 74 65 61 6c 74 68 } //1 tb_stealth
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}