
rule Trojan_Win32_QakbotPacker_AF_MTB{
	meta:
		description = "Trojan:Win32/QakbotPacker.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 08 66 3b ff 74 90 01 01 8b 45 90 01 01 0f b6 44 10 90 01 01 33 c8 3a c0 90 13 8b 45 90 01 01 03 45 90 01 01 88 08 90 13 8b 45 90 01 01 40 90 13 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 73 90 01 01 90 13 8b 45 90 01 01 03 45 90 01 01 0f b6 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}