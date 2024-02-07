
rule Trojan_Win32_Ozopige_A{
	meta:
		description = "Trojan:Win32/Ozopige.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 7a 00 00 00 b8 61 00 00 00 e8 90 01 04 8b d0 8d 45 e4 e8 90 01 04 8b 55 e4 8d 45 ec e8 90 01 04 ff 45 f4 ff 4d e8 75 d4 90 00 } //01 00 
		$a_03_1 = {83 f8 03 74 30 68 90 01 04 6a 00 6a 00 e8 90 01 04 a3 90 01 04 e8 90 01 04 3d b7 00 00 00 0f 84 90 00 } //01 00 
		$a_00_2 = {61 74 74 72 69 62 20 2b 68 20 22 25 73 22 } //01 00  attrib +h "%s"
		$a_00_3 = {23 4d 41 43 41 44 44 52 23 } //00 00  #MACADDR#
	condition:
		any of ($a_*)
 
}