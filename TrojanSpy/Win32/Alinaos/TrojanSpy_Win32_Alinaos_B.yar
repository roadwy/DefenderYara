
rule TrojanSpy_Win32_Alinaos_B{
	meta:
		description = "TrojanSpy:Win32/Alinaos.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {41 6c 69 6e 61 20 76 90 0f 01 00 2e 90 0f 01 00 90 00 } //02 00 
		$a_03_1 = {56 56 56 6a 01 68 90 01 04 ff 15 98 91 41 00 8b d8 89 5d 90 01 01 3b de 0f 84 90 01 04 83 fb ff 0f 84 90 01 04 56 56 6a 03 56 56 6a 50 68 90 01 04 53 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}