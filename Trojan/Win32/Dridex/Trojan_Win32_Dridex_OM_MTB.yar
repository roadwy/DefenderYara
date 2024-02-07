
rule Trojan_Win32_Dridex_OM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 08 8b e5 5d c3 90 09 21 00 33 15 90 01 04 c7 05 90 01 08 01 15 90 01 04 a1 90 01 04 8b 0d 90 00 } //01 00 
		$a_02_1 = {8b 55 08 89 0a a1 90 02 04 8b 90 02 05 8d 90 02 06 89 90 02 05 a1 90 02 04 a3 90 02 04 8b 90 02 05 89 90 02 05 8b 90 02 05 83 90 02 02 89 90 02 05 90 18 e8 90 02 04 8b e5 5d c3 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}