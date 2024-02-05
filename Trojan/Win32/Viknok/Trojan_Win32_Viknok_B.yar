
rule Trojan_Win32_Viknok_B{
	meta:
		description = "Trojan:Win32/Viknok.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 40 6a 06 ff b5 90 01 02 ff ff 83 ee 05 ff 75 08 c6 45 90 01 01 e9 89 75 90 01 01 ff d3 90 00 } //01 00 
		$a_01_1 = {03 c3 8b 70 20 8b 78 1c 8b 50 24 03 f3 03 fb 03 d3 83 78 18 00 } //00 00 
	condition:
		any of ($a_*)
 
}