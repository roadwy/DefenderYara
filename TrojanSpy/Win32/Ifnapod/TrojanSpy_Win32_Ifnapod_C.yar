
rule TrojanSpy_Win32_Ifnapod_C{
	meta:
		description = "TrojanSpy:Win32/Ifnapod.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {75 27 8d 44 24 10 50 ff d5 ff 35 90 01 02 00 10 ff 74 24 18 ff 15 90 01 02 00 10 dc 1d 90 01 02 00 10 83 c4 0c df e0 9e 76 cc eb b3 90 00 } //01 00 
		$a_02_1 = {6a 3e 99 59 f7 f9 46 83 fe 08 8a 82 90 01 02 00 10 88 44 35 c7 7c e4 80 65 d0 00 8d 85 34 fe ff ff 68 90 01 02 00 10 50 ff 15 90 00 } //01 00 
		$a_00_2 = {57 4c 45 76 65 6e 74 4c 6f 67 6f 66 66 00 57 4c 45 76 65 6e 74 4c 6f 67 6f 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}