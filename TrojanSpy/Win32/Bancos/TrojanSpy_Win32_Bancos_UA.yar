
rule TrojanSpy_Win32_Bancos_UA{
	meta:
		description = "TrojanSpy:Win32/Bancos.UA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 3a 20 49 74 61 75 20 42 61 6e 6b 4c 69 6e 65 20 3a 3a } //01 00 
		$a_01_1 = {6f 20 34 30 20 69 6e 76 61 6c 69 64 61 2c 66 61 76 6f 72 20 70 72 65 65 6e 63 68 65 72 20 63 6f 72 72 65 74 61 6d 65 6e 74 65 } //02 00 
		$a_01_2 = {73 65 6e 68 61 31 4b 65 79 50 72 65 73 73 } //01 00 
		$a_01_3 = {53 65 6e 68 61 20 45 6c 65 74 72 6f 6e 69 63 61 20 69 6e 76 61 6c 69 64 61 } //02 00 
		$a_01_4 = {73 65 6e 36 2e 2e 2e 2e 3a } //00 00 
	condition:
		any of ($a_*)
 
}