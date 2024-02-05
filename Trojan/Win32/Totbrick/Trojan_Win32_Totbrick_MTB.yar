
rule Trojan_Win32_Totbrick_MTB{
	meta:
		description = "Trojan:Win32/Totbrick!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c1 2b c3 83 c0 03 a3 90 01 04 bd 03 00 00 00 0f b7 05 90 01 04 89 44 24 18 03 c1 03 fb 81 ff 90 01 04 8d 6c 28 d8 90 00 } //01 00 
		$a_02_1 = {8b c3 2b c1 83 c0 03 8b d0 0f af d3 69 d2 90 01 04 81 c7 90 01 04 89 7d 00 39 15 90 01 04 a3 90 01 04 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Totbrick_MTB_2{
	meta:
		description = "Trojan:Win32/Totbrick!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 ee 08 8b da 8b ce d3 fb 47 85 f6 88 5c 07 ff 75 90 01 01 8b 4c 24 90 01 01 83 c5 04 49 89 4c 24 90 01 01 0f 85 90 01 02 ff ff 90 00 } //01 00 
		$a_02_1 = {33 d2 8b c1 bd 90 01 01 00 00 00 f7 f5 8a 04 1a 30 04 31 41 3b cf 75 90 00 } //01 00 
		$a_02_2 = {33 d2 8b c1 bf 90 01 01 00 00 00 f7 f7 8a 90 01 01 31 8a 90 01 05 32 90 01 01 88 90 01 01 31 41 81 f9 90 01 04 75 90 00 } //01 00 
		$a_02_3 = {33 d2 8b c1 f7 f3 0f b6 04 2a 8b 54 8c 10 03 c7 03 c2 8b f8 81 e7 90 01 04 79 90 00 } //00 00 
		$a_00_4 = {e7 } //4a 00 
	condition:
		any of ($a_*)
 
}