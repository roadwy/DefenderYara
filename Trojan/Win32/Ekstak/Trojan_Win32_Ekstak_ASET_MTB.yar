
rule Trojan_Win32_Ekstak_ASET_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b f0 8d 44 24 0c 50 57 ff 15 90 01 03 00 85 f6 8b f8 74 0c 8d 4c 24 08 51 56 ff 15 90 01 03 00 85 ff 5f 5e 74 12 8b 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}