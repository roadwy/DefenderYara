
rule Trojan_Win64_IcedID_GFS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {89 e8 31 c9 8a 14 0f 88 14 0e 48 ff c1 39 c8 75 f3 48 89 f0 } //0a 00 
		$a_01_1 = {0f be fd 31 c7 41 39 dc 72 1b 8a 45 00 ff c3 4c 01 fd 84 c0 0f 85 19 fd ff ff } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {40 2e 67 65 68 63 6f 6e 74 34 } //01 00  @.gehcont4
		$a_01_4 = {2e 76 6f 6c 74 62 6c } //00 00  .voltbl
	condition:
		any of ($a_*)
 
}