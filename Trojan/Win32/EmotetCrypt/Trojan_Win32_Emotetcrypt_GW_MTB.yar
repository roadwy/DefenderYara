
rule Trojan_Win32_Emotetcrypt_GW_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 1a 03 c2 99 bd 90 01 04 f7 fd a1 90 01 04 8b e9 0f af ce 0f af e8 0f af c8 0f af ef 45 0f af 2d 90 01 04 41 0f af ee 0f af cf 2b cd 8d 04 49 03 d3 8a 0c 10 8b 44 24 90 01 01 30 08 90 00 } //1
		$a_81_1 = {78 61 38 36 75 7a 5a 67 4c 66 42 72 79 4e 2a 55 49 58 35 63 56 57 68 4d 44 73 74 46 5a 2a 39 44 5e 5e 35 31 31 42 36 4e 49 36 4b 64 62 24 30 24 6a 3c 36 67 53 31 6a 73 42 55 49 67 42 76 69 43 28 5f 57 5e 76 73 40 4f 79 3e 71 3f 39 3c 23 73 46 6a 71 2b 3c 6f 66 59 58 58 6a 5f } //1 xa86uzZgLfBryN*UIX5cVWhMDstFZ*9D^^511B6NI6Kdb$0$j<6gS1jsBUIgBviC(_W^vs@Oy>q?9<#sFjq+<ofYXXj_
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}