
rule Trojan_Win32_Ekstak_ASDZ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {56 57 8b 7c 24 10 85 ff 74 24 8b 74 24 0c 85 f6 74 1c e8 90 01 01 ff ff ff 56 ff 15 90 01 02 7e 00 83 c4 04 85 c0 74 90 00 } //02 00 
		$a_01_1 = {8d 44 24 10 6a 10 50 56 c7 44 24 1c 00 00 00 00 ff 15 00 83 7e 00 8b 4c 24 1c 83 c4 0c 85 c9 75 } //00 00 
	condition:
		any of ($a_*)
 
}