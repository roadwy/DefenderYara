
rule TrojanDropper_Win32_VB_EH{
	meta:
		description = "TrojanDropper:Win32/VB.EH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {0c 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 0e 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00 } //01 00 
		$a_00_1 = {6e 00 74 00 64 00 6c 00 6c 00 00 00 28 00 00 00 4e 00 74 00 55 00 6e 00 6d 00 61 00 70 00 56 00 69 00 65 00 77 00 4f 00 66 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00 00 00 } //01 00 
		$a_03_2 = {f5 01 00 00 00 f5 00 00 00 00 f5 00 00 00 00 04 90 01 01 ff 3a e8 fe 1c 00 fb ef f8 fe 3e 90 01 01 ff 46 90 01 01 fe fb ef b0 fe fd fe 90 01 01 ff 04 90 01 01 ff 34 6c 90 01 01 ff f5 00 00 00 00 f5 00 00 00 00 0a 32 00 18 00 3c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}