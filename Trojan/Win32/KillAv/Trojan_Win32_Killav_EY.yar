
rule Trojan_Win32_Killav_EY{
	meta:
		description = "Trojan:Win32/Killav.EY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b de c1 eb 19 c1 e6 07 0f be d2 0b de 33 da } //01 00 
		$a_00_1 = {75 09 66 81 7c 30 fe c7 05 74 15 } //02 00 
		$a_02_2 = {80 c1 fd 88 8e 90 01 03 10 46 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}