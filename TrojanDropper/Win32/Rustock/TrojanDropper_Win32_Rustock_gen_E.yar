
rule TrojanDropper_Win32_Rustock_gen_E{
	meta:
		description = "TrojanDropper:Win32/Rustock.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 13 31 c2 8d 64 24 fc 89 14 24 8f 06 8d 5b 04 83 c6 04 83 e9 01 85 c9 75 19 61 68 90 01 04 c3 90 00 } //01 00 
		$a_00_1 = {8d 80 a2 4a fa 27 eb } //00 00 
	condition:
		any of ($a_*)
 
}