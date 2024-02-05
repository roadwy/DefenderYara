
rule Trojan_Win32_Meteit_E{
	meta:
		description = "Trojan:Win32/Meteit.E,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {c7 45 fc bb bb 00 00 81 7d fc aa aa 00 00 72 04 83 65 fc 00 8b 45 90 01 01 8b 4d 90 00 } //01 00 
		$a_02_1 = {ff 10 33 c9 39 4b 08 0f 85 90 01 04 b8 90 01 04 89 4d f8 2b c6 89 4d fc 89 45 f0 0f 90 00 } //01 00 
		$a_02_2 = {ff 10 33 c0 39 43 08 0f 85 90 01 04 ba 90 01 04 89 45 f8 2b d6 89 45 fc 89 55 f0 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}