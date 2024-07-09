
rule Trojan_Win32_Emotet_DGI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 4d 00 8a 5c 14 1c 32 d9 [0-06] 8b 44 24 14 83 c4 04 88 5d 00 } //1
		$a_81_1 = {58 6c 4a 32 76 44 6d 4d 44 46 4a 6c 4f 72 34 6a 35 49 6d 4b 72 47 42 34 79 63 66 6d 63 4b 44 } //1 XlJ2vDmMDFJlOr4j5ImKrGB4ycfmcKD
		$a_81_2 = {65 49 79 58 30 75 45 56 56 6b 4e 56 4c 61 50 55 53 34 4c 71 5a 50 68 33 71 4f 56 56 79 61 4e 45 35 34 64 } //1 eIyX0uEVVkNVLaPUS4LqZPh3qOVVyaNE54d
		$a_81_3 = {45 75 57 50 63 54 64 79 59 76 45 62 77 48 76 32 42 78 5a 48 6b 4a 30 68 5a 47 46 77 74 34 77 55 50 78 6b 47 4e 50 6f 71 5a 5a 69 62 48 74 35 64 5a 43 62 63 68 } //1 EuWPcTdyYvEbwHv2BxZHkJ0hZGFwt4wUPxkGNPoqZZibHt5dZCbch
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}