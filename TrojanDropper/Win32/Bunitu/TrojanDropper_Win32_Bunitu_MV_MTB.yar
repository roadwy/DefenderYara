
rule TrojanDropper_Win32_Bunitu_MV_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 11 5f 8b e5 5d c3 90 0a 3c 00 50 8f 05 90 01 04 8b 3d 90 02 0f 33 05 90 01 04 8b 90 02 04 89 15 90 01 04 8b 0d 90 01 04 8b 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}