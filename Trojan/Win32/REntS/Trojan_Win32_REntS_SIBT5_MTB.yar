
rule Trojan_Win32_REntS_SIBT5_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIBT5!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 00 83 f0 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 88 01 8b 45 90 1b 01 03 45 90 1b 02 8a 00 2c 90 01 01 8b 4d 90 1b 01 03 4d 90 1b 02 88 01 8b 45 90 1b 01 03 45 90 1b 02 0f b6 00 05 90 01 04 8b 4d 90 1b 01 03 4d 90 1b 02 88 01 8b 45 90 1b 01 03 45 90 1b 02 8a 00 04 90 01 01 8b 4d 90 1b 01 03 4d 90 1b 02 88 01 90 00 } //01 00 
		$a_03_1 = {8b 55 08 b9 3a b6 01 00 90 18 8a 02 84 c0 90 18 6b c9 90 01 01 0f be c0 03 c8 42 8a 02 84 c0 75 90 01 01 8b c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}