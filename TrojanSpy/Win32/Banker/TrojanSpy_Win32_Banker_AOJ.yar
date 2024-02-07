
rule TrojanSpy_Win32_Banker_AOJ{
	meta:
		description = "TrojanSpy:Win32/Banker.AOJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 04 00 "
		
	strings :
		$a_02_0 = {70 00 68 00 70 00 2e 00 90 01 01 61 00 74 00 6c 00 75 00 73 00 6e 00 6f 00 63 00 2f 00 72 00 62 00 2e 00 6d 00 6f 00 63 00 2e 00 90 02 10 2e 00 77 00 77 00 77 00 90 00 } //04 00 
		$a_02_1 = {70 68 70 2e 90 01 01 61 74 6c 75 73 6e 6f 63 2f 72 62 2e 6d 6f 63 2e 90 02 10 2e 77 77 77 90 00 } //01 00 
		$a_00_2 = {4e 6f 76 6f 20 61 63 65 73 73 6f 20 43 6f 6e 6e 65 63 74 20 42 61 6e 6b 2e } //01 00  Novo acesso Connect Bank.
		$a_00_3 = {4e 6f 76 6f 20 61 63 65 73 73 6f 20 48 73 62 63 20 62 61 6e 6b 2d 6c 69 6e 65 2e 2e 2e } //00 00  Novo acesso Hsbc bank-line...
	condition:
		any of ($a_*)
 
}