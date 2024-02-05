
rule TrojanSpy_Win32_AveMaria_G_MTB{
	meta:
		description = "TrojanSpy:Win32/AveMaria.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 ca 8b 45 90 01 01 c7 04 81 90 01 04 eb 90 09 23 00 8b 55 90 01 01 83 c2 90 01 01 89 55 90 01 01 83 7d ec 90 01 01 7d 90 01 01 69 45 f4 90 01 04 8d 8c 05 90 01 04 8b 55 90 01 01 c1 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}