
rule Trojan_Win32_RelineStealer_FT_MTB{
	meta:
		description = "Trojan:Win32/RelineStealer.FT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 85 8c fe ff ff 03 85 90 01 04 89 45 a4 8b 4d b4 0f af 8d 90 01 04 89 8d 90 01 04 8b 95 90 01 04 0f af 95 90 01 04 89 55 f8 8b 45 c4 0f af 85 90 01 04 89 85 90 01 04 8b 8d 90 01 04 3b 8d 24 ff ff ff 7c 0f 90 00 } //0a 00 
		$a_02_1 = {89 8d fc fd ff ff 8b 55 08 83 c2 70 89 95 90 01 04 8b 45 08 05 a6 00 00 00 89 85 90 01 04 8b 4d 08 83 c1 3e 89 8d 90 01 04 8b 55 08 83 c2 1d 89 95 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}