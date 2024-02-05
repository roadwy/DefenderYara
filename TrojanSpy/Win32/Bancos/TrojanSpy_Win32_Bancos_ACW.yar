
rule TrojanSpy_Win32_Bancos_ACW{
	meta:
		description = "TrojanSpy:Win32/Bancos.ACW,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {bf 01 00 00 00 8b 45 f8 0f b6 44 38 ff 03 c6 b9 ff 00 00 00 99 f7 f9 8b da 8b 45 ec 3b 45 f0 7d 05 ff 45 ec eb 07 c7 45 ec 01 00 00 00 83 f3 10 } //02 00 
		$a_01_1 = {64 61 74 61 63 61 64 61 73 74 72 6f 2c 6d 61 63 61 64 64 72 65 73 73 } //01 00 
		$a_01_2 = {49 6e 73 65 72 74 20 69 6e 74 6f 20 54 42 5f } //01 00 
		$a_01_3 = {70 63 6e 61 6d 65 2c } //01 00 
		$a_01_4 = {67 62 75 73 74 65 72 21 } //01 00 
		$a_01_5 = {61 67 65 6e 63 69 61 63 6f 6e 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}