
rule Trojan_Win32_AveMaria_BM_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {8a 04 0f c0 c8 03 32 83 90 02 04 6a 0c 88 04 0f 8d 43 01 99 5e f7 fe 41 8b da 81 f9 90 02 04 7c 90 00 } //01 00 
		$a_03_1 = {6a 40 68 00 10 00 00 68 90 01 02 00 00 57 8b f0 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}