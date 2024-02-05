
rule Trojan_Win32_REntS_SIBT16_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIBT16!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 01 8b 55 90 01 01 03 55 90 01 01 0f b6 02 83 c0 90 01 01 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 90 00 } //01 00 
		$a_03_1 = {88 01 8b 55 90 01 01 03 55 90 01 01 0f b6 02 2d 90 01 04 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 90 00 } //01 00 
		$a_03_2 = {88 01 8b 55 90 01 01 03 55 90 01 01 0f b6 02 35 90 01 04 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 90 00 } //01 00 
		$a_03_3 = {0f be 11 85 d2 74 90 01 01 8b 45 90 01 01 c1 e0 90 01 01 03 45 90 1b 01 8b 4d 08 0f be 11 03 c2 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}