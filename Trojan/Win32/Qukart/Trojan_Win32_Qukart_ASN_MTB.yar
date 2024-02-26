
rule Trojan_Win32_Qukart_ASN_MTB{
	meta:
		description = "Trojan:Win32/Qukart.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 6a 47 6d 79 41 49 71 } //01 00  bjGmyAIq
		$a_01_1 = {52 41 76 62 6f 77 61 74 4b } //01 00  RAvbowatK
		$a_01_2 = {57 6e 45 4d 6d 4b 44 78 } //01 00  WnEMmKDx
		$a_01_3 = {6e 69 4c 70 55 53 74 77 } //01 00  niLpUStw
		$a_01_4 = {46 63 45 4e 57 54 61 51 32 } //01 00  FcENWTaQ2
		$a_01_5 = {5a 69 63 66 75 6f 74 45 } //01 00  ZicfuotE
		$a_01_6 = {6c 70 73 47 58 57 6a 74 } //01 00  lpsGXWjt
		$a_01_7 = {56 62 7a 55 4a 41 43 55 } //01 00  VbzUJACU
		$a_01_8 = {67 44 4b 4a 6e 6b 64 69 } //01 00  gDKJnkdi
		$a_01_9 = {47 46 62 69 59 69 44 46 } //00 00  GFbiYiDF
	condition:
		any of ($a_*)
 
}