
rule Trojan_Win32_Niugpy_A{
	meta:
		description = "Trojan:Win32/Niugpy.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 7e d2 b1 61 74 04 } //01 00 
		$a_03_1 = {81 ff 78 ea ff ff 75 0a 8b 45 20 e8 90 01 04 eb 90 01 01 81 ff 0e 01 00 00 90 00 } //01 00 
		$a_01_2 = {25 f0 00 ff ff 05 88 ff 00 00 c1 e0 10 50 68 0a 02 00 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}