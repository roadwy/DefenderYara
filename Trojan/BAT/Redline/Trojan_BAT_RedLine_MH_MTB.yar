
rule Trojan_BAT_RedLine_MH_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 03 16 11 03 8e 69 6f 90 01 03 0a 13 06 38 90 01 04 14 13 06 20 01 00 00 00 28 90 01 03 06 3a 90 01 04 26 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_RedLine_MH_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 90 01 03 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 90 00 } //5
		$a_01_1 = {39 38 61 34 32 61 31 35 2d 63 31 36 65 2d 34 35 63 65 2d 62 34 62 63 2d 63 30 35 64 30 34 65 38 32 66 31 66 } //2 98a42a15-c16e-45ce-b4bc-c05d04e82f1f
		$a_01_2 = {4d 69 6e 65 73 77 65 65 70 65 72 5f 57 69 6e 64 6f 77 73 2e 50 72 6f 70 65 72 74 69 65 73 } //2 Minesweeper_Windows.Properties
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}
rule Trojan_BAT_RedLine_MH_MTB_3{
	meta:
		description = "Trojan:BAT/RedLine.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 fd a2 3d 09 0f 00 00 00 f8 00 31 00 06 00 00 01 00 00 00 5d } //10
		$a_01_1 = {4d 65 6d 62 65 72 52 65 66 73 50 72 6f 78 79 } //1 MemberRefsProxy
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_5 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}