
rule Trojan_Win32_SpyStealer_AO_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 45 fc 8b 45 fc 8a 04 38 8b 0d 90 02 04 88 04 0f 83 3d 90 02 04 44 75 10 90 00 } //02 00 
		$a_03_1 = {03 c3 33 45 fc 33 c1 81 3d 90 02 08 89 45 fc 75 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}