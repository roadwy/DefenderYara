
rule Trojan_Win32_REntS_SIBT6_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIBT6!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 00 83 f0 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 00 } //0a 00 
		$a_03_1 = {88 01 8b 45 90 01 01 03 45 90 01 01 0f b6 00 83 c0 90 01 01 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 90 00 } //0a 00 
		$a_03_2 = {88 01 8b 45 90 01 01 03 45 90 01 01 8a 00 2c 90 01 01 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 90 00 } //01 00 
		$a_03_3 = {8b 55 08 b9 3a b6 01 00 90 18 8a 02 84 c0 90 18 6b c9 90 01 01 0f be c0 03 c8 42 8a 02 84 c0 75 90 01 01 8b c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}