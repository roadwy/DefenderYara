
rule Trojan_Win32_Duqu_E{
	meta:
		description = "Trojan:Win32/Duqu.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 02 06 24 ae 74 07 33 c0 e9 } //01 00 
		$a_03_1 = {66 8b 01 ba 90 01 04 66 33 c2 8b 54 24 08 66 89 02 74 16 57 41 41 66 8b 01 42 42 bf 90 01 04 66 33 c7 66 89 02 75 ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}