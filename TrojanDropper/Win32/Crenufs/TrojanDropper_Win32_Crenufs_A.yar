
rule TrojanDropper_Win32_Crenufs_A{
	meta:
		description = "TrojanDropper:Win32/Crenufs.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 83 c9 fc 41 8a 54 14 14 8a 5c 0c 10 32 d3 8a 98 90 01 04 32 da 88 98 90 01 04 8b 0d 90 01 04 40 3b c1 72 bf 90 00 } //01 00 
		$a_01_1 = {ff d7 8b c8 bb 03 00 00 00 99 f7 fb 85 d2 75 0f 8b c1 b9 19 00 00 00 99 f7 f9 80 c2 61 eb 1e } //01 00 
		$a_01_2 = {3a 66 75 6e 63 73 69 7a 65 00 } //00 00  昺湵獣穩e
	condition:
		any of ($a_*)
 
}