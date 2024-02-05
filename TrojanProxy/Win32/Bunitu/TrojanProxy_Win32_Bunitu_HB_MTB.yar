
rule TrojanProxy_Win32_Bunitu_HB_MTB{
	meta:
		description = "TrojanProxy:Win32/Bunitu.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 04 a1 90 01 04 a3 90 01 04 8b 0d 90 01 04 8b 15 90 01 04 8d 44 0a 03 2b 85 90 01 04 03 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 83 e9 03 89 0d 90 01 04 8b 15 90 01 04 2b 15 90 01 04 89 15 90 01 04 a1 90 01 04 03 05 90 01 04 a3 90 01 04 83 3d 90 01 04 00 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}