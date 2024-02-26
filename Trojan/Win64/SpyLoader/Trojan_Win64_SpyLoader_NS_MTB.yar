
rule Trojan_Win64_SpyLoader_NS_MTB{
	meta:
		description = "Trojan:Win64/SpyLoader.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 69 6d 62 6f 74 20 76 69 73 69 62 6c 65 } //01 00  Aimbot visible
		$a_01_1 = {63 6f 6e 66 69 67 2e 64 61 74 } //01 00  config.dat
		$a_01_2 = {53 68 6f 77 20 46 6f 76 } //01 00  Show Fov
		$a_01_3 = {61 69 6d 62 6f 74 } //01 00  aimbot
		$a_01_4 = {41 50 45 58 2e 70 64 62 } //00 00  APEX.pdb
	condition:
		any of ($a_*)
 
}