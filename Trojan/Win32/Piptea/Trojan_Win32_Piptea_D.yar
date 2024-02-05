
rule Trojan_Win32_Piptea_D{
	meta:
		description = "Trojan:Win32/Piptea.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 48 28 89 4d 90 01 01 ff 55 90 00 } //01 00 
		$a_03_1 = {8d 45 dc 50 ff 15 90 01 04 83 7d f0 00 76 18 90 00 } //01 00 
		$a_01_2 = {c7 45 c0 b9 79 37 9e } //00 00 
	condition:
		any of ($a_*)
 
}