
rule TrojanDropper_Win32_Jeshex_A{
	meta:
		description = "TrojanDropper:Win32/Jeshex.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 d0 80 fa 00 74 } //01 00 
		$a_01_1 = {ff 75 14 6a 02 6a 00 6a 00 68 00 00 00 c0 } //01 00 
		$a_01_2 = {ff 75 18 6a 00 ff 75 28 68 } //00 00 
	condition:
		any of ($a_*)
 
}