
rule TrojanSpy_Win32_Tnega_MTB{
	meta:
		description = "TrojanSpy:Win32/Tnega!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 84 24 ac 00 00 00 30 84 0c ad 00 00 00 41 83 f9 1a 72 } //01 00 
		$a_01_1 = {30 4c 05 f5 40 83 f8 0a 73 05 8a 4d f4 eb } //01 00 
		$a_01_2 = {8a 45 b2 30 44 0d b3 41 83 f9 34 72 } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}