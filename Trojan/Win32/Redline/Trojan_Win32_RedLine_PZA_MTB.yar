
rule Trojan_Win32_RedLine_PZA_MTB{
	meta:
		description = "Trojan:Win32/RedLine.PZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 e0 03 0f b6 80 90 01 04 30 81 90 01 04 8d 82 90 01 04 03 c1 83 e0 03 0f b6 80 90 01 04 30 81 90 01 04 8d 86 90 01 04 03 c1 83 e0 03 0f b6 80 90 01 04 30 81 90 01 04 8d 87 90 01 04 03 c1 83 e0 90 00 } //01 00 
		$a_03_1 = {8b c8 83 e1 90 01 01 0f b6 89 90 01 04 30 88 90 01 04 8d 8a 90 01 04 03 c8 83 e1 03 0f b6 89 90 01 04 30 88 90 01 04 83 c0 02 3d 7e 07 00 00 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}