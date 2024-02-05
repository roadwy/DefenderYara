
rule Trojan_Win32_Racealer_R_MTB{
	meta:
		description = "Trojan:Win32/Racealer.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 e8 1e a2 90 01 04 0f be 0d 90 01 04 83 e9 14 88 0d 90 01 04 0f be 15 90 01 04 83 ea 14 88 15 90 01 04 0f be 05 90 01 04 83 e8 1e a2 90 00 } //01 00 
		$a_00_1 = {8b 45 0c 01 45 fc 8b 45 08 8b 4d fc 33 08 8b 55 08 89 0a } //00 00 
	condition:
		any of ($a_*)
 
}