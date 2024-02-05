
rule TrojanDropper_Win32_Bunitu_MX_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c7 33 05 90 01 04 8b c8 8b d1 89 15 90 01 04 8b 15 90 01 04 a1 90 01 04 89 02 5f 8b e5 5d c3 90 09 13 00 50 8f 05 90 01 04 8b 3d 90 01 04 89 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}