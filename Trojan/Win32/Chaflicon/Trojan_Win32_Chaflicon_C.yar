
rule Trojan_Win32_Chaflicon_C{
	meta:
		description = "Trojan:Win32/Chaflicon.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 17 89 d0 33 d2 89 17 8b e8 ff d5 83 3f 00 75 90 01 01 83 3d 90 01 04 00 74 11 e8 90 00 } //01 00 
		$a_00_1 = {5b 56 45 52 53 41 4f 4c 4f 41 44 45 52 5d } //01 00 
		$a_00_2 = {5b 4c 49 4e 4b 43 4f 4e 54 41 44 4f } //01 00 
		$a_00_3 = {5b 46 54 50 55 53 45 52 5d } //01 00 
		$a_00_4 = {5b 4c 49 4e 4b 45 58 45 5d } //00 00 
		$a_00_5 = {5d 04 00 } //00 df 
	condition:
		any of ($a_*)
 
}