
rule Trojan_Win32_Wastker_WR_MTB{
	meta:
		description = "Trojan:Win32/Wastker.WR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 2d 25 64 2d 73 65 72 76 65 72 } //01 00  %c%c%c%c%c%c%c%c%cMS-%d-server
		$a_03_1 = {8b c2 8d 0c 3a 83 e0 03 42 8a 80 90 01 04 32 04 0e 88 01 3b d3 7c 90 00 } //01 00 
		$a_03_2 = {68 0e 27 00 00 ff d6 85 db 74 90 01 01 ff 90 01 01 33 db eb 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}