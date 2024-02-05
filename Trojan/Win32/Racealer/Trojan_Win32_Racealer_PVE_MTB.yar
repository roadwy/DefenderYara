
rule Trojan_Win32_Racealer_PVE_MTB{
	meta:
		description = "Trojan:Win32/Racealer.PVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b c5 c1 e8 05 03 44 24 90 01 01 03 d5 33 ca 81 3d 90 01 04 72 07 00 00 c7 05 90 01 04 b4 1a 3a df 89 1d 90 01 04 89 1d 90 01 04 89 4c 24 10 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}