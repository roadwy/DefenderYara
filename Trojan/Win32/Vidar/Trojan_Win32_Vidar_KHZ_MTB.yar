
rule Trojan_Win32_Vidar_KHZ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.KHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 6c 24 2c 8b 5c 24 30 8b 7c 24 28 8b 4c 24 38 8a 44 2c 3c 88 44 1c 3c 8a 44 24 90 01 01 88 44 2c 3c 0f b6 44 1c 3c 03 44 24 34 0f b6 c0 8a 44 04 3c 30 04 39 8b 44 24 90 01 01 85 c0 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}