
rule TrojanSpy_Win32_Bancos_AHX{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 6e 46 56 38 6a 4c 58 2b 2f 53 42 78 76 4a 59 4b 41 43 70 67 31 64 6a 73 74 4e } //01 00 
		$a_01_1 = {58 6a 6d 5a 38 7a 42 6b 35 6e 51 6c 78 4b 79 63 62 41 61 57 30 43 37 46 48 2b 66 42 52 4f 4b 48 48 48 63 54 6a 2b 36 62 32 59 68 32 6e 62 30 45 4c 6a 45 62 73 76 67 58 44 74 52 53 } //01 00 
		$a_01_2 = {66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 66 ff 4c 24 04 75 c5 } //00 00 
	condition:
		any of ($a_*)
 
}