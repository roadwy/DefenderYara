
rule TrojanSpy_Win32_Banker_MV{
	meta:
		description = "TrojanSpy:Win32/Banker.MV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {40 67 6f 72 64 6f 2e 63 6f 6d 2e 62 72 } //01 00 
		$a_02_1 = {61 6e 74 72 61 78 5f 90 10 06 00 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d 90 00 } //01 00 
		$a_00_2 = {45 2d 42 61 6e 6b 69 6e 67 20 69 6e 73 74 61 6c 61 64 6f 20 63 6f 6d 20 73 75 63 65 73 73 6f } //01 00 
		$a_02_3 = {68 74 74 70 3a 2f 2f 6c 69 6e 6b 61 6e 64 6f 2e 6f 72 67 66 72 65 65 2e 63 6f 6d 2f 90 02 06 2e 74 78 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}