
rule TrojanSpy_Win32_Banker_ZW{
	meta:
		description = "TrojanSpy:Win32/Banker.ZW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 00 72 00 61 00 64 00 65 00 73 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00  bradesco.com.br
		$a_00_1 = {44 69 67 69 74 65 20 73 75 61 20 73 65 6e 68 61 } //01 00  Digite sua senha
		$a_02_2 = {61 00 67 00 65 00 6e 00 63 00 69 00 61 00 90 02 20 76 00 61 00 6c 00 75 00 65 00 90 02 10 63 00 6f 00 6e 00 74 00 61 00 90 02 10 64 00 61 00 63 00 90 02 10 73 00 65 00 6e 00 68 00 61 00 90 02 10 43 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 65 00 72 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}