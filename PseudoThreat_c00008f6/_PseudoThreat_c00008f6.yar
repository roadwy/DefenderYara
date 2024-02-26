
rule _PseudoThreat_c00008f6{
	meta:
		description = "!PseudoThreat_c00008f6,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 89 44 24 90 01 01 89 4c 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8d 14 2e 31 54 24 90 01 01 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}