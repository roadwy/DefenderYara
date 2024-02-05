
rule Trojan_Win32_Racealer_AA_MTB{
	meta:
		description = "Trojan:Win32/Racealer.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 01 c3 31 08 c3 81 3d 90 01 04 e6 01 00 00 90 02 10 8b 44 24 04 33 44 24 08 c2 08 00 81 00 12 37 ef c6 c3 90 00 } //01 00 
		$a_03_1 = {8b d6 d3 ea 03 c6 50 90 02 20 31 45 f4 2b 7d f4 90 02 1c 8b c7 c1 e8 05 03 cf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}