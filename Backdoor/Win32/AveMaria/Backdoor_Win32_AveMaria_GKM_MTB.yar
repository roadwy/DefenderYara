
rule Backdoor_Win32_AveMaria_GKM_MTB{
	meta:
		description = "Backdoor:Win32/AveMaria.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c2 01 89 55 ?? 8b 45 ?? 3b 85 ?? ?? ?? ?? 7d ?? 8b 45 ?? 99 f7 bd ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 0f be 11 8b 85 ?? ?? ?? ?? 0f be 4c 05 ?? 33 d1 8b 45 ?? 03 45 ?? 88 10 eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}