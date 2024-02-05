
rule Trojan_Win32_Carmapic_C{
	meta:
		description = "Trojan:Win32/Carmapic.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 00 1e 00 00 00 8b 16 8d 85 28 fe ff ff b9 90 01 04 e8 90 01 04 8b 9d 28 fe ff ff 89 9d 24 fe ff ff 8b 85 24 fe ff ff e8 90 01 04 50 e8 90 01 04 83 f8 01 1b c0 40 8b 16 8d 85 20 fe ff ff b9 90 01 04 e8 90 01 04 8b 85 20 fe ff ff e8 90 01 04 84 c0 75 aa 90 00 } //01 00 
		$a_03_1 = {74 3e 68 f4 01 00 00 e8 90 01 04 8b 15 90 01 04 8b 12 8d 45 f0 b9 90 01 04 e8 90 01 04 8b 5d f0 89 5d ec 8b 45 ec e8 90 01 04 50 e8 90 01 04 83 f8 01 1b c0 40 90 00 } //01 00 
		$a_01_2 = {68 69 64 65 2e 62 61 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}