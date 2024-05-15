
rule Trojan_Win32_Ekstak_ASFS_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {51 56 ff 15 90 01 03 00 8b f0 ff 15 90 01 03 00 85 ff a3 90 01 03 00 74 27 85 f6 74 12 8b 15 90 01 03 00 68 90 01 03 00 52 ff 15 90 01 03 00 8d 44 24 08 50 57 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}