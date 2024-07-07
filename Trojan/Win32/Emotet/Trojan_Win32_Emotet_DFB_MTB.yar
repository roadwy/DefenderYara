
rule Trojan_Win32_Emotet_DFB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 c1 0f b6 4d 0f 89 85 90 01 04 8b 45 f0 0f b6 84 05 90 01 04 03 c1 8b cb 99 f7 f9 8b 85 90 1b 00 8a 8c 15 90 1b 01 30 08 90 00 } //1
		$a_02_1 = {57 53 ff 15 90 01 04 8b f8 8b 45 90 01 01 c1 e0 03 53 50 68 00 30 00 00 57 53 ff 15 90 01 04 50 ff d6 8b f0 90 00 } //1
		$a_81_2 = {74 75 70 46 59 6b 4c 42 48 54 6a 55 73 34 4a 36 46 62 72 42 4f 48 71 44 43 34 61 32 68 38 62 4f } //1 tupFYkLBHTjUs4J6FbrBOHqDC4a2h8bO
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}