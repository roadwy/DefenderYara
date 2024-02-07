
rule Trojan_Win32_Staser_PEF_MTB{
	meta:
		description = "Trojan:Win32/Staser.PEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 c0 0f a2 89 45 fc 89 5d f8 89 4d ec 89 55 f0 b8 01 00 00 00 0f a2 } //05 00 
		$a_01_1 = {3d 47 65 6e 75 75 1b 8b 45 f0 3d 69 6e 65 49 75 11 8b 45 ec 3d 6e 74 65 6c } //05 00 
		$a_01_2 = {8b 84 24 00 02 00 00 83 c8 40 89 84 24 00 02 00 00 0f ae 94 24 00 02 00 00 81 c4 08 02 00 00 } //01 00 
		$a_01_3 = {40 2e 73 65 6c 62 } //01 00  @.selb
		$a_01_4 = {2e 73 65 6c 61 } //00 00  .sela
	condition:
		any of ($a_*)
 
}