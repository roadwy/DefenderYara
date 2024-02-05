
rule VirTool_Win64_PplFault_A{
	meta:
		description = "VirTool:Win64/PplFault.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {45 33 c0 48 8b 90 01 06 48 8b 90 01 0a e8 90 01 04 45 33 c9 45 33 c0 48 8b 90 00 } //01 00 
		$a_01_1 = {48 83 ec 38 41 b8 04 00 00 00 33 d2 b9 ff ff 1f } //01 00 
		$a_03_2 = {40 53 48 83 ec 90 01 01 48 8b 51 90 01 01 48 8b d9 48 83 fa 90 01 01 72 2c 48 8b 09 48 ff c2 48 81 fa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}