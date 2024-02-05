
rule TrojanSpy_Win32_Bancos_VQ{
	meta:
		description = "TrojanSpy:Win32/Bancos.VQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 00 f3 00 70 00 69 00 61 00 20 00 64 00 65 00 20 00 43 00 45 00 46 00 5c 00 56 00 42 00 42 00 48 00 4f 00 2e 00 76 00 62 00 70 00 } //01 00 
		$a_01_1 = {47 62 61 73 2e 64 6c 6c 00 44 6c 6c } //01 00 
		$a_03_2 = {47 62 61 73 00 90 03 03 06 47 41 53 48 65 6c 70 65 72 00 00 59 61 68 6f 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}