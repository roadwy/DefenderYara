
rule Trojan_Win32_Oficla_AE{
	meta:
		description = "Trojan:Win32/Oficla.AE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 bd f4 fe ff ff 61 63 73 2e 74 28 } //01 00 
		$a_01_1 = {c6 45 f6 78 c6 45 f5 25 c6 45 f4 75 c6 45 f3 25 c6 45 f7 00 } //01 00 
		$a_01_2 = {0f b7 83 94 01 00 00 33 83 96 01 00 00 0d 00 00 00 80 } //01 00 
		$a_01_3 = {8b 14 87 01 da 80 3a 47 75 ea 80 7a 03 50 75 e4 80 7a 07 41 75 de } //00 00 
	condition:
		any of ($a_*)
 
}