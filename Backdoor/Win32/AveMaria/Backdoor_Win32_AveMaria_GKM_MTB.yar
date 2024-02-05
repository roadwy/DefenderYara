
rule Backdoor_Win32_AveMaria_GKM_MTB{
	meta:
		description = "Backdoor:Win32/AveMaria.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c2 01 89 55 90 01 01 8b 45 90 01 01 3b 85 90 01 04 7d 90 01 01 8b 45 90 01 01 99 f7 bd 90 01 04 89 95 90 01 04 8b 4d 90 01 01 03 4d 90 01 01 0f be 11 8b 85 90 01 04 0f be 4c 05 90 01 01 33 d1 8b 45 90 01 01 03 45 90 01 01 88 10 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}