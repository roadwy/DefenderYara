
rule Trojan_Win32_AveMaria_GV_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 11 88 10 eb 90 01 01 8b 45 90 01 01 03 85 90 01 04 0f b6 08 8b 95 90 01 04 33 8c 95 90 01 04 8b 85 90 01 04 03 85 90 01 04 88 08 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}