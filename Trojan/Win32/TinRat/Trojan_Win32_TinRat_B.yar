
rule Trojan_Win32_TinRat_B{
	meta:
		description = "Trojan:Win32/TinRat.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 01 00 00 00 8b 1d 58 81 40 00 03 1d 6c 81 40 00 53 68 90 01 04 e8 96 00 00 00 68 01 00 00 00 a1 60 81 40 00 89 c3 03 1d 68 81 40 00 53 68 90 01 04 e8 79 00 00 00 8b 1d 90 01 04 33 1d 90 01 04 89 1d 90 01 04 68 01 00 00 00 68 90 01 04 8b 1d 58 81 40 00 03 1d 6c 81 40 00 53 e8 4b 00 00 00 ff 05 68 81 40 00 8b 1d 68 81 40 00 3b 1d 64 81 40 00 7e 0a c7 05 68 81 40 00 00 00 00 00 83 05 6c 81 40 00 03 e9 5d ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}