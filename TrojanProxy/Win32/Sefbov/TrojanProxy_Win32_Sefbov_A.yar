
rule TrojanProxy_Win32_Sefbov_A{
	meta:
		description = "TrojanProxy:Win32/Sefbov.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 f5 5a 75 04 c6 45 f5 5b } //01 00 
		$a_01_1 = {68 28 0a 00 00 a3 08 30 40 00 } //01 00 
		$a_01_2 = {38 39 2e 31 30 37 2e 31 30 34 } //00 00  89.107.104
	condition:
		any of ($a_*)
 
}