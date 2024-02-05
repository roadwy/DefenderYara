
rule Trojan_Win32_Vochs_A{
	meta:
		description = "Trojan:Win32/Vochs.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 76 63 68 c7 90 01 02 6f 73 74 2e c7 90 01 02 65 78 65 00 90 00 } //01 00 
		$a_01_1 = {b9 0b 00 00 00 fc f3 a6 74 65 8d } //01 00 
		$a_01_2 = {b9 7f 00 00 00 32 c0 f2 ae 4f } //00 00 
	condition:
		any of ($a_*)
 
}