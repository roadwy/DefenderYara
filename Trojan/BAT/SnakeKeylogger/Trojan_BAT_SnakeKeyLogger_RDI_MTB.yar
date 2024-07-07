
rule Trojan_BAT_SnakeKeyLogger_RDI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 36 65 35 63 35 65 36 2d 37 65 34 37 2d 34 63 30 31 2d 39 30 63 65 2d 33 35 35 38 35 63 65 34 30 36 32 37 } //1 46e5c5e6-7e47-4c01-90ce-35585ce40627
		$a_01_1 = {56 42 47 56 37 36 } //1 VBGV76
		$a_01_2 = {63 33 63 35 34 63 61 63 65 35 65 39 63 32 63 35 62 31 65 61 30 66 38 35 65 30 39 65 33 34 30 31 65 } //1 c3c54cace5e9c2c5b1ea0f85e09e3401e
		$a_01_3 = {56 00 6b 00 4a 00 48 00 56 00 6a 00 63 00 32 00 4a 00 41 00 3d 00 3d 00 } //1 VkJHVjc2JA==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}