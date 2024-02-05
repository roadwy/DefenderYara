
rule Trojan_Win32_Vundo_OV{
	meta:
		description = "Trojan:Win32/Vundo.OV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 61 63 75 75 72 65 2e 64 6c 6c 00 61 63 43 6c 69 65 6e 74 } //01 00 
		$a_02_1 = {8b 48 28 85 c9 74 14 a1 90 01 04 6a 00 03 c8 6a 02 50 89 0d 90 01 04 ff d1 90 00 } //01 00 
		$a_00_2 = {8b 4d fc 66 83 79 0c 08 74 05 b8 06 00 00 00 85 c0 75 0c 8d 55 f8 52 ff 73 08 e8 } //00 00 
	condition:
		any of ($a_*)
 
}