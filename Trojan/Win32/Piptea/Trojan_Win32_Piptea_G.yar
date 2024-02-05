
rule Trojan_Win32_Piptea_G{
	meta:
		description = "Trojan:Win32/Piptea.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 ee 02 57 6a 00 5f 74 90 01 01 53 90 03 04 05 bb 90 01 04 68 90 01 04 5b 57 68 90 01 04 53 e8 90 01 04 83 c4 0c 47 47 83 c3 08 90 00 } //01 00 
		$a_01_1 = {83 c6 28 4f 75 } //00 00 
	condition:
		any of ($a_*)
 
}