
rule Trojan_Win32_Waltrodock_B{
	meta:
		description = "Trojan:Win32/Waltrodock.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 6b 74 44 72 69 76 65 72 2e 70 64 62 } //01 00  RktDriver.pdb
		$a_01_1 = {8d b0 80 16 01 00 33 db f3 a6 74 07 40 3b c2 7e e7 } //01 00 
		$a_01_2 = {7d 2a 8d 43 ff 3b c8 8d 04 89 8d 34 c2 74 05 8b 46 34 eb 03 } //00 00 
	condition:
		any of ($a_*)
 
}