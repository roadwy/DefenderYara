
rule Trojan_Win32_Urocflood_A{
	meta:
		description = "Trojan:Win32/Urocflood.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 69 2e 25 69 2e 25 69 2e 25 69 00 } //02 00 
		$a_03_1 = {68 39 05 00 00 66 89 46 02 ff 90 01 04 00 68 39 05 00 00 89 46 04 ff 90 01 04 00 68 39 05 00 00 89 46 08 66 c7 46 0c 50 02 ff 90 01 04 00 8b 55 08 66 89 46 0e 90 00 } //00 00 
		$a_00_2 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}