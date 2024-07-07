
rule Trojan_Win32_IcedId_DAS_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {2a cb 02 c1 8b 4c 24 18 89 39 8b 7c 24 0c 83 c7 04 89 7c 24 0c 81 ff 07 12 00 00 0f } //5
		$a_01_1 = {44 65 73 65 72 74 70 69 63 6b } //1 Desertpick
		$a_01_2 = {52 75 6e 62 6f 6f 6b } //1 Runbook
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_Win32_IcedId_DAS_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {53 6a 01 53 8d 45 90 01 01 53 50 89 5d 0c ff 15 90 01 04 85 c0 75 90 01 01 6a 08 6a 01 53 8d 45 90 1b 00 53 50 ff 15 90 1b 01 85 c0 90 00 } //1
		$a_81_1 = {45 6d 31 4f 37 63 63 73 44 48 41 51 45 55 6a } //1 Em1O7ccsDHAQEUj
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}