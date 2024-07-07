
rule TrojanDropper_Win32_Frethog_E{
	meta:
		description = "TrojanDropper:Win32/Frethog.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 08 50 68 73 00 09 00 ff 76 2c ff 15 90 01 03 00 85 c0 74 09 6a 01 89 9e 98 61 00 00 58 90 00 } //1
		$a_00_1 = {c7 44 37 fc 4b 43 55 46 89 30 8b c7 5f } //1
		$a_03_2 = {83 7d fc 64 73 90 01 01 6a 02 53 6a fc 58 2b 45 fc 50 ff 75 f4 ff d6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}