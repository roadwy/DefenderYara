
rule PWS_Win32_Mapdimp_D{
	meta:
		description = "PWS:Win32/Mapdimp.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 04 00 "
		
	strings :
		$a_03_0 = {6a 02 57 6a fc 53 ff d6 8d 45 f8 57 50 8d 45 f4 6a 04 50 53 8b 1d 90 01 04 ff d3 81 7d f4 90 01 04 74 0e 90 00 } //01 00 
		$a_10_1 = {76 65 72 63 6c 73 69 64 } //01 00  verclsid
		$a_01_2 = {c7 45 ec 6f 6b 00 00 ff 15 } //01 00 
		$a_01_3 = {c7 45 ec 5f 4d 42 00 50 } //00 00 
	condition:
		any of ($a_*)
 
}