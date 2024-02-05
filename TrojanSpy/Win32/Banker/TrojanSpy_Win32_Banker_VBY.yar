
rule TrojanSpy_Win32_Banker_VBY{
	meta:
		description = "TrojanSpy:Win32/Banker.VBY,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f4 7d 03 46 eb 05 be 01 } //02 00 
		$a_01_1 = {89 45 f4 33 f6 bb 00 01 00 00 8d 55 dc b8 } //03 00 
		$a_01_2 = {78 73 65 72 76 69 63 65 78 00 } //01 00 
		$a_01_3 = {5c 76 65 72 73 61 6f 2e 74 78 74 00 } //01 00 
		$a_01_4 = {67 6d 61 69 6c 2e 74 78 74 00 } //01 00 
		$a_01_5 = {6d 73 6e 2e 74 78 74 00 } //01 00 
		$a_01_6 = {63 61 69 78 61 65 62 61 6e 6b 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}