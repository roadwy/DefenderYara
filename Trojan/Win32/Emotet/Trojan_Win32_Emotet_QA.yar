
rule Trojan_Win32_Emotet_QA{
	meta:
		description = "Trojan:Win32/Emotet.QA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 13 68 01 00 01 00 ff 15 90 01 04 85 c0 90 00 } //01 00 
		$a_03_1 = {00 75 f0 51 e8 90 09 31 00 b8 90 01 04 a3 90 01 04 a3 90 01 04 33 c0 21 05 90 01 04 a3 90 01 04 39 05 90 01 04 74 18 40 a3 90 01 04 83 3c c5 90 00 } //01 00 
		$a_03_2 = {02 03 01 00 01 00 00 90 09 65 00 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}