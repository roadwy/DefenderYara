
rule Trojan_Win32_Autophyte_E_dha{
	meta:
		description = "Trojan:Win32/Autophyte.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {af c6 44 24 90 02 01 3d c6 90 01 03 78 c6 90 01 03 23 c6 90 01 03 4a c6 90 01 03 79 c6 90 01 03 92 c6 90 01 03 81 c6 90 01 03 9d c6 90 00 } //01 00 
		$a_03_1 = {af c6 84 24 90 02 04 3d c6 90 02 06 78 c6 90 02 06 23 c6 90 02 06 4a c6 90 02 06 79 c6 90 02 06 92 c6 90 02 06 81 c6 90 02 06 9d c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}