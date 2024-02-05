
rule Trojan_Win32_SpyStealer_AR_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 84 07 36 23 01 00 8b 0d 90 02 04 88 04 0f 81 3d 90 02 04 66 0c 00 00 75 0b 90 00 } //02 00 
		$a_03_1 = {83 ff 26 75 05 e8 90 02 04 47 81 ff b7 c4 3d 00 7c ed 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}