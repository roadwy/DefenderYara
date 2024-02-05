
rule Trojan_Win32_Racealer_F_MTB{
	meta:
		description = "Trojan:Win32/Racealer.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {c1 e2 04 89 11 c3 8b c1 33 c2 c3 81 01 cc 36 ef c6 c3 29 11 c3 01 11 c3 } //01 00 
		$a_02_1 = {8b c3 d3 e0 8d 90 02 25 8b c3 c1 e8 05 8d 90 02 25 33 45 90 02 30 b6 0c 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}