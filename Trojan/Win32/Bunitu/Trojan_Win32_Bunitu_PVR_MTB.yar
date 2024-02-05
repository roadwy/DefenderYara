
rule Trojan_Win32_Bunitu_PVR_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.PVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b c8 8b d1 89 15 90 01 04 8b 15 90 01 04 a1 90 01 04 89 02 5f 8b e5 5d 90 09 0a 00 8b c7 eb 90 01 01 33 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}