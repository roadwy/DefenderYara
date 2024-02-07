
rule Trojan_BAT_AgentTesla_ABBM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_1 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_3 = {24 62 63 35 38 35 30 64 63 2d 38 64 30 35 2d 34 66 64 38 2d 39 32 66 66 2d 36 32 64 65 30 64 66 62 38 34 36 36 } //01 00  $bc5850dc-8d05-4fd8-92ff-62de0dfb8466
		$a_01_4 = {4d 00 6f 00 73 00 65 00 72 00 77 00 61 00 72 00 65 00 32 00 30 00 32 00 32 00 32 00 30 00 32 00 32 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  Moserware20222022.Properties.Resources
		$a_01_5 = {42 00 57 00 54 00 6f 00 70 00 43 00 } //01 00  BWTopC
		$a_01_6 = {63 00 68 00 65 00 65 00 73 00 65 00 } //01 00  cheese
		$a_01_7 = {44 00 65 00 73 00 65 00 72 00 74 00 47 00 75 00 79 00 } //00 00  DesertGuy
	condition:
		any of ($a_*)
 
}