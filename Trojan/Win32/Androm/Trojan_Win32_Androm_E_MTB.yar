
rule Trojan_Win32_Androm_E_MTB{
	meta:
		description = "Trojan:Win32/Androm.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 e8 6a cc f9 ff 4b 75 f6 bb 90 02 06 6a 00 e8 5b cc f9 ff 4b 75 f6 6a 00 90 00 } //01 00 
		$a_00_1 = {55 8b ec 90 90 8b 45 08 8a 10 80 f2 7b 88 10 5d c2 } //01 00 
		$a_02_2 = {8b 06 03 c3 73 05 e8 90 02 06 50 ff 15 90 02 06 90 90 ff 06 81 3e 90 02 06 75 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}