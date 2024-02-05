
rule TrojanSpy_Win32_Banker_VBD{
	meta:
		description = "TrojanSpy:Win32/Banker.VBD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {40 67 6d 61 69 6c 2e 63 6f 6d } //01 00 
		$a_00_1 = {6d 73 6e 5f 6c 69 76 65 72 73 2e 65 78 65 } //02 00 
		$a_03_2 = {83 c4 f0 b8 90 01 02 48 00 e8 90 01 03 ff a1 90 01 02 48 00 8b 00 e8 90 01 03 ff 68 90 01 02 48 00 6a 00 e8 90 01 03 ff 85 c0 75 58 a1 90 01 02 48 00 8b 00 ba 90 01 02 48 00 e8 90 01 03 ff 8b 0d 90 01 02 48 00 a1 90 01 02 48 00 8b 00 8b 15 90 01 02 47 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}