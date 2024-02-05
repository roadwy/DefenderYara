
rule TrojanDropper_Win32_Bunitu_MU_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 90 01 04 8b 15 90 01 04 8b 3d 90 01 04 33 d7 8b ca 8b c1 c7 45 90 01 08 a1 90 01 04 8b 4d 90 01 01 89 08 5f 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}