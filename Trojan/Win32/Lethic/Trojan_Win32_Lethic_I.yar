
rule Trojan_Win32_Lethic_I{
	meta:
		description = "Trojan:Win32/Lethic.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 89 01 68 90 01 04 8b 55 90 01 01 52 ff 15 90 01 04 8b 4d 08 89 41 04 90 00 } //01 00 
		$a_03_1 = {8b 55 08 8b 82 90 01 01 01 00 00 ff d0 3d 33 27 00 00 75 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}