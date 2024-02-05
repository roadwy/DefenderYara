
rule TrojanSpy_Win32_Bancos_ZP{
	meta:
		description = "TrojanSpy:Win32/Bancos.ZP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 77 00 69 00 6e 00 46 00 69 00 6c 00 65 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_1 = {43 00 6f 00 6d 00 70 00 75 00 74 00 61 00 64 00 6f 00 72 00 2e 00 2e 00 2e 00 2e 00 3a 00 } //01 00 
		$a_01_2 = {2e 00 3a 00 3a 00 2e 00 49 00 4e 00 46 00 45 00 43 00 54 00 2e 00 3a 00 3a 00 2e 00 } //01 00 
		$a_01_3 = {63 4f 64 65 72 46 65 6e 72 69 72 } //00 00 
	condition:
		any of ($a_*)
 
}