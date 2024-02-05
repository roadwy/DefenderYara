
rule Trojan_Win32_Neurevt_C{
	meta:
		description = "Trojan:Win32/Neurevt.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {c7 45 f0 e6 9c 18 ee c7 45 f4 c8 8a 25 1d c7 45 f8 00 02 ab 7f c7 45 fc 10 00 05 ff } //01 00 
		$a_03_1 = {64 a1 30 00 00 00 53 56 85 c0 74 90 01 01 80 78 02 01 74 90 00 } //01 00 
		$a_01_2 = {8a 4d fc 30 0c 18 40 3b c7 72 f5 } //00 00 
		$a_00_3 = {87 10 00 } //00 38 
	condition:
		any of ($a_*)
 
}