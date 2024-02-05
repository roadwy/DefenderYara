
rule Trojan_Win32_Fareit_SK_eml{
	meta:
		description = "Trojan:Win32/Fareit.SK!eml,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c0 8d 14 03 80 32 30 40 3d 09 5c 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_SK_eml_2{
	meta:
		description = "Trojan:Win32/Fareit.SK!eml,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 0c 30 8a 09 90 80 f1 38 8d 1c 30 88 0b 40 4a 75 ed } //00 00 
	condition:
		any of ($a_*)
 
}