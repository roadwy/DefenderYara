
rule Trojan_Win32_SpyStealer_AX_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 4d f0 83 c1 01 89 4d f0 8b 55 f0 3b 55 0c 73 1c 0f b6 05 90 02 04 8b 4d 08 03 4d f0 0f b6 11 2b d0 8b 45 08 03 45 f0 88 10 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}