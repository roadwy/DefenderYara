
rule Trojan_Win32_GraceWire_BL_dha{
	meta:
		description = "Trojan:Win32/GraceWire.BL!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {c7 45 fc 00 00 00 00 8b 45 08 33 45 0c 89 45 08 c1 45 08 04 8b 4d 08 81 c1 78 77 77 77 89 4d 08 8b 45 08 } //01 00 
		$a_02_1 = {c7 45 fc 00 00 00 00 8b 45 08 33 45 0c 89 45 08 c1 45 08 04 8b 4d 08 81 c1 90 01 04 89 4d 08 8b 45 08 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}