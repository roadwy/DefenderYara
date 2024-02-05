
rule Trojan_Win32_Racealer_DPS_MTB{
	meta:
		description = "Trojan:Win32/Racealer.DPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b cb c1 e1 04 03 4c 24 90 01 01 8b c3 c1 e8 05 03 44 24 90 01 01 8d 3c 1e 33 cf c7 05 90 01 04 b4 1a 3a df 89 4c 24 10 81 fa 72 07 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}