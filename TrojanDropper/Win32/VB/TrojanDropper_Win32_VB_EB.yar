
rule TrojanDropper_Win32_VB_EB{
	meta:
		description = "TrojanDropper:Win32/VB.EB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {0c 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 0e 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00 } //01 00 
		$a_00_1 = {4e 00 74 00 55 00 6e 00 6d 00 61 00 70 00 56 00 69 00 65 00 77 00 4f 00 66 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //01 00  NtUnmapViewOfSection
		$a_03_2 = {80 0c 00 4a ec f4 02 eb fe 6e 60 ff 58 00 6c 78 ff 1b 2e 00 28 40 ff 02 00 6f 70 ff e8 80 0c 00 0b 90 01 04 23 3c ff 2a 23 38 ff 0a 90 01 04 e8 0b 90 01 04 23 34 ff 2a 31 78 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}