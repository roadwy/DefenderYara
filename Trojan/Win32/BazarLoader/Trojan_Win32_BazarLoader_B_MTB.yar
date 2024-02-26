
rule Trojan_Win32_BazarLoader_B_MTB{
	meta:
		description = "Trojan:Win32/BazarLoader.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 11 88 55 90 01 01 0f b6 45 90 01 01 c1 f8 90 01 01 0f b6 4d 90 01 01 c1 e1 90 01 01 0b c1 0f b6 55 90 01 01 33 c2 8b 4d 90 00 } //02 00 
		$a_03_1 = {8b 45 dc 83 c0 90 01 01 99 b9 90 01 04 f7 f9 89 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}