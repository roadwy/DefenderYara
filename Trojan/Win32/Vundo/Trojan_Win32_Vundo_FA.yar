
rule Trojan_Win32_Vundo_FA{
	meta:
		description = "Trojan:Win32/Vundo.FA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6e 65 74 20 73 74 6f 70 20 77 69 6e 73 73 00 } //01 00 
		$a_00_1 = {6e 65 74 20 73 74 6f 70 20 4f 63 48 65 61 6c 74 68 4d 6f 6e 00 } //01 00 
		$a_03_2 = {50 53 53 6a 26 53 33 f6 ff 15 90 01 02 00 10 68 90 01 02 00 10 8d 45 90 01 01 50 ff 15 90 01 02 00 10 8d 45 90 01 01 50 ff 15 90 01 02 00 10 8b f8 3b fb 74 90 01 01 68 90 01 02 00 10 57 ff 15 90 01 02 00 10 3b c3 74 90 01 01 53 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}