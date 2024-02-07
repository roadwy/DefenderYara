
rule TrojanSpy_Win32_Shiotob_C{
	meta:
		description = "TrojanSpy:Win32/Shiotob.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 42 65 73 74 2e 70 64 66 } //01 00  \Best.pdf
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 51 00 75 00 6f 00 74 00 69 00 65 00 } //01 00  http://Quotie
		$a_01_2 = {6d 00 65 00 61 00 73 00 75 00 72 00 2e 00 54 00 75 00 72 00 6e 00 } //01 00  measur.Turn
		$a_01_3 = {2e 00 53 00 69 00 6c 00 65 00 6e 00 74 00 } //02 00  .Silent
		$a_03_4 = {6a 00 6a 00 6a 01 6a 00 6a 02 68 00 00 00 40 8d 8d d8 fe ff ff 51 ff 15 90 01 04 89 45 f0 8b 55 ec 83 ea 1b 81 fa d5 00 00 00 76 17 8b 45 ec 03 05 90 01 04 0f b7 0d 90 01 04 03 c1 a3 90 01 04 83 7d f0 ff 74 17 6a 01 6a 00 6a 00 8d 95 d8 fe ff ff 52 6a 00 6a 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}