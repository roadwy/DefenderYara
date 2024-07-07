
rule Trojan_Win32_Racealer_GKM_MTB{
	meta:
		description = "Trojan:Win32/Racealer.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb 74 19 00 00 8b 15 90 01 04 8a 8c 32 90 01 04 8b 15 90 01 04 88 0c 32 3d 03 02 00 00 75 90 01 01 6a 00 6a 00 ff d7 a1 90 01 04 89 1d 90 01 04 46 3b f0 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Racealer_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/Racealer.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 55 90 01 01 8b 45 90 01 01 01 45 90 01 01 81 3d 90 01 04 c6 0e 00 00 75 90 01 01 6a 00 6a 00 ff 15 90 01 04 8b 45 90 01 01 33 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 01 01 8b 55 90 01 01 2b 55 90 01 01 89 55 90 01 01 8b 45 90 01 01 29 45 90 01 01 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Racealer_GKM_MTB_3{
	meta:
		description = "Trojan:Win32/Racealer.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 55 90 01 01 8b 45 90 01 01 01 45 90 01 01 81 3d 90 01 04 8f 0c 00 00 75 90 01 01 68 90 01 04 6a 00 ff 15 90 01 04 8b 45 90 01 01 33 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 01 01 8b 55 90 01 01 2b 55 90 01 01 89 55 90 01 01 8b 45 90 01 01 29 45 90 01 01 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}