
rule Backdoor_Win32_SolarMarker_ARA_MTB{
	meta:
		description = "Backdoor:Win32/SolarMarker.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 03 45 f0 89 45 e8 8a 45 f0 8b 55 e8 32 02 32 45 ee 0f b7 55 ee 8b 4d f4 8a 54 11 ff 2a c2 0f b7 55 ee 8b 4d f4 8a 54 11 ff 32 c2 8b 55 e8 88 02 8b 45 f4 } //00 00 
	condition:
		any of ($a_*)
 
}