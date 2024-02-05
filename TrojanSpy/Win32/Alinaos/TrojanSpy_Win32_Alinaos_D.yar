
rule TrojanSpy_Win32_Alinaos_D{
	meta:
		description = "TrojanSpy:Win32/Alinaos.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {41 6c 69 6e 61 20 76 90 0f 01 00 2e 90 0f 01 00 90 00 } //02 00 
		$a_03_1 = {53 57 6a 00 6a 00 6a 00 6a 01 68 90 01 04 89 45 90 01 01 89 4d 90 01 01 8b fa c7 45 90 01 01 00 00 00 00 ff 15 90 01 04 8b d8 89 5d 90 01 01 85 db 0f 84 90 01 04 83 fb ff 0f 84 90 01 04 56 6a 00 6a 00 6a 03 6a 00 6a 00 6a 50 68 90 01 04 53 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}