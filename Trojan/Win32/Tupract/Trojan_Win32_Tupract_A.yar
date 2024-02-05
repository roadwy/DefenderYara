
rule Trojan_Win32_Tupract_A{
	meta:
		description = "Trojan:Win32/Tupract.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 75 70 25 78 25 78 2e 74 6d 70 00 } //01 00 
		$a_03_1 = {6a 00 56 ff d3 25 ff 00 00 00 c1 e0 10 83 c8 01 50 56 68 00 01 00 00 57 ff d5 68 c8 00 00 00 ff 15 90 01 04 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}