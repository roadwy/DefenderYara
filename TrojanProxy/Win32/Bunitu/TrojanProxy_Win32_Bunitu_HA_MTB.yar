
rule TrojanProxy_Win32_Bunitu_HA_MTB{
	meta:
		description = "TrojanProxy:Win32/Bunitu.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 5f 33 00 00 85 c0 74 90 01 01 8b 4d 90 01 01 3b 0d 90 01 04 72 90 01 01 eb 90 01 01 8b 75 90 01 01 03 75 90 01 01 68 50 11 00 00 ff 15 90 01 04 03 f0 68 50 11 00 00 ff 15 90 01 04 03 f0 8b 55 90 01 01 03 55 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 8a 0c 31 88 0c 10 8b 55 90 01 01 83 c2 01 89 55 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}