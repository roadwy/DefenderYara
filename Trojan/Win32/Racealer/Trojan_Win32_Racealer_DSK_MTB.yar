
rule Trojan_Win32_Racealer_DSK_MTB{
	meta:
		description = "Trojan:Win32/Racealer.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e9 05 03 4d e4 89 45 fc 89 1d 90 01 04 89 1d 90 01 04 8b 45 e0 31 45 fc 81 3d 90 01 04 72 07 00 00 75 90 00 } //02 00 
		$a_02_1 = {8b cb c1 e9 05 03 4d e0 89 45 fc 89 35 90 01 04 89 35 90 01 04 8b 45 dc 31 45 fc 81 3d 90 01 04 72 07 00 00 75 90 00 } //02 00 
		$a_02_2 = {8b c7 c1 e8 05 03 45 90 01 01 03 cb 03 d7 33 ca 81 3d 90 01 04 72 07 00 00 89 35 90 01 04 89 35 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}