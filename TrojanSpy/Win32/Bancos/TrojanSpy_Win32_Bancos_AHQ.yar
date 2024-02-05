
rule TrojanSpy_Win32_Bancos_AHQ{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHQ,SIGNATURE_TYPE_PEHSTR_EXT,67 00 66 00 04 00 00 64 00 "
		
	strings :
		$a_01_0 = {52 65 61 6c 74 65 6b 20 48 44 20 41 75 64 69 6f 20 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 00 00 50 5f 52 65 61 6c 54 41 43 50 } //01 00 
		$a_00_1 = {5c 00 41 00 4b 00 3a 00 5c 00 6e 00 6e 00 6e 00 6e 00 63 00 5c 00 50 00 5f 00 52 00 65 00 61 00 6c 00 54 00 41 00 43 00 50 00 2e 00 76 00 62 00 70 00 } //01 00 
		$a_01_2 = {45 72 72 6f 72 00 46 75 6e 63 5f 50 6f 73 74 6f } //01 00 
		$a_01_3 = {66 81 e3 ff 00 8b f8 89 55 84 c7 85 7c ff ff ff 08 00 00 00 79 09 66 4b 66 81 cb 00 ff 66 43 0f bf c3 } //00 00 
	condition:
		any of ($a_*)
 
}