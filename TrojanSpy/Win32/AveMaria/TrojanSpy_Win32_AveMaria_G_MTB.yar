
rule TrojanSpy_Win32_AveMaria_G_MTB{
	meta:
		description = "TrojanSpy:Win32/AveMaria.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 ca 8b 45 ?? c7 04 81 ?? ?? ?? ?? eb 90 09 23 00 8b 55 ?? 83 c2 ?? 89 55 ?? 83 7d ec ?? 7d ?? 69 45 f4 ?? ?? ?? ?? 8d 8c 05 ?? ?? ?? ?? 8b 55 ?? c1 e2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}