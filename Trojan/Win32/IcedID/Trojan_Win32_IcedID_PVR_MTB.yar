
rule Trojan_Win32_IcedID_PVR_MTB{
	meta:
		description = "Trojan:Win32/IcedID.PVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b f0 89 15 90 01 04 81 05 90 01 04 10 4c 08 02 6b ed 1f 8b 44 24 24 03 6c 24 28 8b 0d 90 01 04 89 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}