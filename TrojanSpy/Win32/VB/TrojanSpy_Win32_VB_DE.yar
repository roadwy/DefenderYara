
rule TrojanSpy_Win32_VB_DE{
	meta:
		description = "TrojanSpy:Win32/VB.DE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5b 00 50 00 61 00 67 00 65 00 44 00 6f 00 77 00 6e 00 5d 00 } //01 00  [PageDown]
		$a_00_1 = {6d 00 6b 00 64 00 69 00 72 00 20 00 2f 00 70 00 75 00 62 00 6c 00 69 00 63 00 5f 00 68 00 74 00 6d 00 6c 00 2f 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 2f 00 } //01 00  mkdir /public_html/Keylogg/
		$a_01_2 = {50 69 63 46 6f 72 6d 61 74 33 32 61 2e 50 69 63 46 6f 72 6d 61 74 33 32 } //00 00  PicFormat32a.PicFormat32
	condition:
		any of ($a_*)
 
}