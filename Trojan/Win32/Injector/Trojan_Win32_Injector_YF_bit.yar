
rule Trojan_Win32_Injector_YF_bit{
	meta:
		description = "Trojan:Win32/Injector.YF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 04 58 69 c0 90 02 04 8b 4d dc c7 04 01 90 02 04 6a 04 58 69 c0 90 02 04 8b 4d dc c7 04 01 90 02 04 6a 04 58 69 c0 90 02 04 8b 4d dc c7 04 01 90 00 } //01 00 
		$a_03_1 = {0b c0 74 02 ff e0 68 90 01 04 b8 90 01 04 ff d0 ff e0 90 00 } //01 00 
		$a_01_2 = {8b 45 08 8b 00 ff 75 08 ff 50 08 8b 45 fc 8b 4d ec 64 89 0d 00 00 00 00 5f 5e 5b c9 c2 04 00 } //00 00 
	condition:
		any of ($a_*)
 
}